import datetime

from dissect.sql import sqlite3
from dissect.sql.exceptions import NoCellData, InvalidPageType
from dissect.esedb.tools import searchindex
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import (
    FilesystemError,
    PluginError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

from functools import lru_cache
from dissect.ntfs.c_ntfs import c_ntfs
from pprint import pprint
import binascii

SearchIndexFileInfoRecord = TargetRecordDescriptor(
    "filesystem/windows/searchindex/fileinformation",
    [
        ("string", "workid"),  # remove me
        ("datetime", "record_last_modified"),
        ("string", "filename"),
        ("datetime", "gathertime"),
        ("varint", "SDID"),  # TODO: Check if this could be more human readable
        ("varint", "size"),
        ("string", "date_modified"),
        ("string", "date_created"),
        ("string", "owner"),
        ("string", "systemitemtype"),
        ("string", "fileattributes"),
        ("string", "autosummary"),
        ("path", "source"),
        ("string", "latest"),
        ("varint", "checkpointindex"),
    ],
)

SearchIndexFileActivityRecord = TargetRecordDescriptor(
    "filesystem/windows/searchindex/fileactivity",
    [
        ("string", "workid"),  # remove me
        ("string", "file_contenturi"),
        ("datetime", "starttime"),
        ("datetime", "endtime"),
        ("string", "appid"),
        ("string", "description"),
        ("string", "displaytext"),
        ("string", "itempathdisplay"),
        ("string", "systemitemtype"),
        ("path", "source"),
        ("string", "latest"),
        ("varint", "checkpointindex"),
    ],  # TODO: Who performed
)

FILES = [
    "Applications/Windows/Windows.edb",  # Windows 10
    "Applications/Windows/Windows.db",  # Windows 11 (ish? Doesn't seem to be consistent in all Win 11 implementations)
]

EVENTLOG_REGISTRY_KEY = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search"

WIN_DATETIME_FIELDS = [
    "LastModified",
    "System_Search_GatherTime",
    "System_DateModified",
    "System_DateCreated",
    "System_ActivityHistory_EndTime",
    "System_ActivityHistory_StartTime",
]

PROPSTORE_INCLUDE_COLUMNS = [
    "WorkID",
    "System_Size",
    "System_DateModified",
    "System_DateCreated",
    "System_FileOwner",
    "System_ItemPathDisplay",
    "System_ItemType",
    "System_FileAttributes",
    "System_Search_AutoSummary",
    "System_Activity_ContentUri",
    "System_Activity_Description",
    "System_Activity_DisplayText",
    "System_ActivityHistory_StartTime",
    "System_ActivityHistory_EndTime",
    "System_ActivityHistory_AppId",
]


class SearchIndexPlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self._files = []
        try:
            datadir = self.target.registry.key(EVENTLOG_REGISTRY_KEY).value("DataDirectory").value
        except RegistryKeyNotFoundError:
            self.target.log.error('No Windows Search registry key "%s" found', EVENTLOG_REGISTRY_KEY)
            return
        except PluginError:
            self.target.log.error("Cannot access registry in target")
            return
        # print(datadir)
        # print(self.target.fs.path(datadir + "Windows.db").exists())
        for filename in FILES:
            databasepath = self.target.resolve(datadir + filename)
            # print(databasepath.lower())
            if target.fs.path(databasepath.lower()).exists():
                self._files.append(target.fs.path(databasepath))

    def check_compatible(self):
        if not self._files:
            raise UnsupportedPluginError("No SearchIndex database files found")

    def _get_edb_records(self, fh) -> list[dict]:
        """
        Get records from an EDB file
        Depends on dissect.esedb/dissect/esedb/tools/searchindex.py
        Gathers all interesting fields from the SystemIndex_Gthr and SystemIndex_PropertyStore tables and combines them into one dict
        """

        si = searchindex.SearchIndex(fh)
        gthr_table_rows = list(  # Get all interesting columns from the Gthr table
            si.get_table_records("SystemIndex_Gthr", include_columns=["DocumentID", "LastModified", "SDID"])
        )
        gthr_rows = {row["DocumentID"]: row for row in gthr_table_rows}  # Create a dict with DocumentID as key

        propstore_table_rows = list(  # Get all interesting columns from the PropStore table
            si.get_table_records(
                "SystemIndex_PropertyStore",
                include_columns=PROPSTORE_INCLUDE_COLUMNS,
            )
        )
        propstore_rows = {row["WorkID"]: row for row in propstore_table_rows}  # Create a dict with WorkID as key

        rows = []
        max_id = max(max(gthr_rows.keys()), max(propstore_rows.keys()))  # Get the highest ID from both dicts
        for iterator in range(max_id):  # Iterate over the highest ID
            row = {"WorkID": iterator}
            if iterator in gthr_rows:  # If the ID is in the gthr_rows dict, add it to the row
                row = row | gthr_rows[iterator]
            if iterator in propstore_rows:  # If the ID is in the propstore_rows dict, add it to the row
                row = row | propstore_rows[iterator]
            if len(row) > 1:  # If the row has more than one key, add it to the rows list
                rows.append(row)
        return rows

    def _get_sqlite_records(self, path) -> list[dict]:
        """
        Get records from a SQLite file
        Gathers all interesting fields from the SystemIndex_Gthr and
        SystemIndex_PropertyStore tables and combines them into one dict
        """

        db = sqlite3.SQLite3(path.open("rb"))  # Open the base SQLite file
        if (sqlite_db_wal := self.target.fs.path(str(path) + "-wal")).exists():  # If a WAL file exists, open it
            db_wal = sqlite3.SQLite3(path.open("rb"))  # Open the SQLite file again but with the WAL file
            db_wal.open_wal(sqlite_db_wal.open())
            # TODO: Add check in following code to make sure the plugin runs without a WAL file
        else:
            db_wal = None

        gather_file = self.target.fs.path(
            "sysvol/programdata/microsoft/search/data/applications/windows/Windows-gather.db"
        )
        gather_db = sqlite3.SQLite3(gather_file.open("rb"))
        if (gather_db_wal := self.target.fs.path(str(gather_file) + "-wal")).exists():
            gather_db.open_wal(gather_db_wal.open())

        # Define gthr_records as a dict with DocumentID as key and a dict with FileName, LastModified and SDID as value
        gthr_table_rows = sorted(list(gather_db.table("SystemIndex_Gthr")), key=lambda x: x["DocumentID"])
        gthr_records = {}
        for row in gthr_table_rows:
            if (last_modified := row["LastModified"]) is not None:
                last_modified = wintimestamp(int.from_bytes(last_modified, "little"))
            gthr_records[row["DocumentID"]] = {
                "FileName": row["FileName"],
                "LastModified": last_modified,
                "SDID": row["SDID"],
            }
        print(gthr_records[3607])
        input()
        propstore_table_metadata = list(db.table("SystemIndex_1_PropertyStore_Metadata"))

        # Create a workable metadata dict with the column name as value and the column id as key
        propstore_metadata = {}
        for row in propstore_table_metadata:
            column_name = row["PropertyId"].replace(".", "_")
            if column_name in PROPSTORE_INCLUDE_COLUMNS:
                propstore_metadata[row["Id"]] = column_name

        propstore_table_rows = sorted(list(db.table("SystemIndex_1_PropertyStore")), key=lambda x: x["WorkId"])

        propstore_records = {}
        for row in propstore_table_rows:
            work_id = row["WorkId"]
            if row["ColumnId"] not in propstore_metadata:
                continue
            if (column_name := propstore_metadata[row["ColumnId"]]) in WIN_DATETIME_FIELDS:
                if (value := row["Value"]) is not None:
                    try:
                        value = wintimestamp(int.from_bytes(value, "little"))
                    except ValueError:
                        value = None
            else:
                value = row["Value"]
            if work_id not in propstore_records.keys():
                propstore_records[work_id] = [{column_name: value, "checkpointindex": 0}]
            else:
                propstore_records[work_id][0][column_name] = value
        pprint(propstore_records[3607])
        input()
        if db_wal:
            for checkpoint in db_wal.wal.checkpoints:
                # print("CHECKPOINT", checkpoint.index)
                rows = get_rows_from_checkpoint(checkpoint)
                for row in rows:  # row = [workid, columnid, value]
                    if row[1] == 3607:
                        print(row)
                    # print(row)
                    work_id = row[0]
                    if row[1] not in propstore_metadata:
                        continue
                    if (column_name := propstore_metadata[row[1]]) in WIN_DATETIME_FIELDS:
                        if (value := row[2]) is not None:
                            try:
                                value = wintimestamp(int.from_bytes(value, "little"))
                            except ValueError:
                                value = None
                    else:
                        value = row[2]

                    if work_id not in propstore_records.keys():
                        propstore_records[work_id] = [{column_name: value, "checkpointindex": checkpoint.index}]
                    elif propstore_records[work_id][-1]["checkpointindex"] < checkpoint.index:
                        if propstore_records[work_id][-1].get(column_name) == value:
                            # print("Not new. skipping")
                            continue
                        new_dict = propstore_records[work_id][-1].copy()
                        new_dict["checkpointindex"] = checkpoint.index
                        propstore_records[work_id].append(new_dict)
                        propstore_records[work_id][-1][column_name] = value
                    else:
                        propstore_records[work_id][-1][column_name] = value
        print("CHECK DONE")
        input()
        # for record in propstore_records:
        #     if len(propstore_records[record]) > 1:
        #         pprint(propstore_records[record])
        #         input()
        # pprint(gthr_records[3607])
        # input()

        # if db_wal:
        #     for checkpoint in db_wal.wal.checkpoints:
        #         diff = get_changes_between_db_and_checkpoint(db, checkpoint)
        #         print(checkpoint.index, get_workid_from_checkpoint(checkpoint))
        #         # pprint(diff)

        #         for row in diff:  # row = [workid, columnid, value]
        #             if row[1] not in propstore_metadata:  # If the column id is not in the metadata dict, skip the row
        #                 continue
        #             if (
        #                 column_name := propstore_metadata[row[1]]
        #             ) in WIN_DATETIME_FIELDS:  # If the column is a datetime field, convert the value to a datetime object
        #                 if (value := row[2]) is not None:
        #                     try:
        #                         value = wintimestamp(int.from_bytes(value, "little"))
        #                     except ValueError:
        #                         value = None
        #             else:
        #                 value = row[2]  # If the column is not a datetime field, just use the value
        #             print(row, column_name, value)
        #             if row[0] not in propstore_records.keys():
        #                 # If the workid is not in the propstore_records dict, add it.
        #                 # This happens if the WAL contains new workids(/files) which aren't present in the base SQLite file.
        #                 propstore_records[row[0]] = [
        #                     {
        #                         column_name: value,
        #                         "checkpointindex": checkpoint.index,
        #                     }
        #                 ]
        #             else:
        #                 if propstore_records[row[0]][-1]["checkpointindex"] < checkpoint.index:
        #                     new_dict = propstore_records[row[0]][-1].copy()
        #                     new_dict["checkpointindex"] = checkpoint.index
        #                     propstore_records[row[0]].append(new_dict)
        #                 propstore_records[row[0]][-1][column_name] = value
        #             input()

        rows = []
        max_id = max(max(gthr_records.keys()), max(propstore_records.keys()))  # Get the highest ID from both dicts
        for iterator in range(max_id):  # Iterate over the highest ID
            row = {"WorkID": iterator}
            if iterator in gthr_records:  # If the ID is in the gthr_rows dict, add it to the row
                row = row | gthr_records[iterator]
            if iterator in propstore_records:  # If the ID is in the propstore_rows dict, add it to the row
                for record in propstore_records[iterator]:
                    rows.append(row | record | {"latest": False})
                rows[-1]["latest"] = True
            elif len(row) > 1:  # If the row has more than one key, add it to the rows list
                rows.append(row)
        return rows

    @export(record=SearchIndexFileInfoRecord)
    def searchindex(self):
        """
        Get records from the SearchIndex database files

        """
        for path in self._files:
            fh = path.open("rb")
            if path.name.endswith(".edb"):
                records = self._get_edb_records(fh)
            elif path.name.endswith(".db"):
                records = self._get_sqlite_records(path)

            for record in records:
                if (systemitemtype := record.get("System_ItemType")) == "ActivityHistoryItem":
                    yield SearchIndexFileActivityRecord(
                        workid=record.get("WorkID"),
                        starttime=record.get("System_ActivityHistory_StartTime"),
                        endtime=record.get("System_ActivityHistory_EndTime"),
                        appid=record.get("System_ActivityHistory_AppId"),
                        file_contenturi=record.get("System_Activity_ContentUri"),
                        description=record.get("System_Activity_Description"),
                        displaytext=record.get("System_Activity_DisplayText"),
                        itempathdisplay=record.get("System_ItemPathDisplay"),
                        systemitemtype=systemitemtype,
                        latest=record.get("latest"),
                        source=path,
                        checkpointindex=record.get("checkpointindex"),
                        _target=self.target,
                    )
                else:
                    if not (filename := record.get("System_ItemPathDisplay")) is None:
                        filename = filename.replace("\\", "/")
                    if not (autosummary := record.get("System_Search_AutoSummary")) is None:
                        autosummary = autosummary.encode("utf-8").hex()
                    if not (fileattributes := record.get("System_FileAttributes")) is None:
                        fileattributes = str(c_ntfs.FILE_ATTRIBUTE(fileattributes)).replace("FILE_ATTRIBUTE.", "")
                    yield SearchIndexFileInfoRecord(
                        workid=record.get("WorkID"),
                        record_last_modified=record.get("LastModified"),
                        filename=filename,
                        gathertime=record.get("System_Search_GatherTime"),
                        SDID=record.get("SDID"),
                        size=int.from_bytes(record.get("System_Size"), "little")
                        if record.get("System_Size") is not None
                        else None,
                        date_modified=record.get("System_DateModified"),
                        date_created=record.get("System_DateCreated"),
                        owner=record.get("System_FileOwner"),
                        systemitemtype=systemitemtype,
                        fileattributes=fileattributes,
                        autosummary=autosummary,
                        latest=record.get("latest"),
                        source=path,
                        checkpointindex=record.get("checkpointindex"),
                        _target=self.target,
                    )


def get_workid_from_checkpoint(checkpoint):
    workids = set()
    for frame in checkpoint.frames:
        try:
            for cell in frame.page.cells():
                try:
                    workids.add(cell.values[0])
                except NoCellData:
                    pass
        except InvalidPageType:
            pass
    return list(workids)


def get_changes_between_db_and_checkpoint(db, checkpoint):
    different_values = []
    for frame in checkpoint.frames:
        try:
            if (db_page := db.page(frame.page_number)) is None:
                db_cell_values = []
            else:
                # print("CHECKPOINT", checkpoint.index, "- DB_PAGE", frame.page_number, db_page.header.flags)
                db_cell_values = [cell.values if cell.size is not None else [] for cell in db_page.cells()]
        except InvalidPageType:
            db_cell_values = []

        try:
            checkpoint_page = frame.page
            # print("CHECKPOINT", checkpoint.index, "- CHECK_PAGE", frame.page_number, db_page.header.flags)
        except (InvalidPageType, AttributeError):
            checkpoint_page = None

        try:
            checkpoint_cell_values = [cell.values for cell in checkpoint_page.cells()]
        except (NoCellData, AttributeError):
            checkpoint_cell_values = []

        for value in checkpoint_cell_values:
            if value not in db_cell_values:
                different_values.append(value)

    return different_values


def get_rows_from_checkpoint(checkpoint):
    rows = []
    for frame in checkpoint.frames:
        try:
            if frame.page.header.flags != 0xA:
                continue
            for cell in frame.page.cells():
                if cell.size > 255:  # Most likely a large blob and so not related to PropertyStore
                    return []
                rows.append(cell.values)
        except InvalidPageType:
            pass
    return rows
