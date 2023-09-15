import datetime

from dissect.sql import sqlite3
from dissect.esedb.tools import searchindex
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

from functools import lru_cache
from dissect.ntfs.c_ntfs import c_ntfs

SearchIndexFileInfoRecord = TargetRecordDescriptor(
    "filesystem/windows/searchindex/fileinformation",
    [
        ("datetime", "record_last_modified"),
        ("string", "filename"),
        ("datetime", "gathertime"),
        ("varint", "SDID"),     # TODO: Check if this could be more human readable
        ("varint", "size"),
        ("string", "date_modified"),
        ("string", "date_created"),
        ("string", "owner"),
        ("string", "systemitemtype"),
        ("string", "fileattributes"),
        ("string", "autosummary"),
    ],
)

SearchIndexFileActivityRecord = TargetRecordDescriptor(
    "filesystem/windows/searchindex/fileactivity",
    [
        ("string", "file_contenturi"),
        ("datetime", "starttime"),
        ("datetime", "endtime"),
        ("string", "appid"),
        ("string", "description"),
        ("string", "displaytext"),
        ("string", "itempathdisplay"),
        ("string", "systemitemtype")
    ],                                      # TODO: Who performed
)

FILES = {
    "sysvol/programdata/microsoft/search/data/applications/windows/Windows.edb",  # Windows 10
    "sysvol/programdata/microsoft/search/data/applications/windows/Windows.db",  # Windows 11
}

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
    "System_Search_GatherTime",
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
    "System_ItemPathDisplay"
]


class SearchIndexPlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self._files = []
        for path in FILES:
            if target.fs.path(path).exists():
                self._files.append(target.fs.path(path))

    def check_compatible(self):
        print(self._files, len(self._files))
        if not self._files:
            raise UnsupportedPluginError("No SearchIndex database files found")

    @lru_cache(maxsize=128)
    def _get_sqlite_column_name_propstore(self, column_id: int):
        if not (column_name := next((x["Name"] for x in self.propstore_metadata if x["Id"] == column_id), False)):
            self.target.log.exception(f"Error while gathering PropStore column name for column id {column_id}")
        return column_name

    def _get_edb_records(self, fh):
        si = searchindex.SearchIndex(fh)
        gthr_table_rows = list(si.get_table_records("SystemIndex_Gthr", include_columns=["DocumentID", "LastModified", "SDID"]))
        gthr_records = {row["DocumentID"]: row for row in gthr_table_rows}

        propstore_table_rows = list(
            si.get_table_records(
                "SystemIndex_PropertyStore",
                include_columns=PROPSTORE_INCLUDE_COLUMNS,
            )
        )
        propstore_records = {row["WorkID"]: row for row in propstore_table_rows}
        records = []
        last_gthr_id = list(gthr_records.keys())[-1]
        last_propstore_id = list(propstore_records.keys())[-1]
        for iterator in range(0, (last_gthr_id if last_gthr_id > last_propstore_id else last_propstore_id)):
            record = {"WorkID": iterator}
            if iterator in gthr_records:
                record = record | gthr_records[iterator]
            if iterator in propstore_records:
                record = record | propstore_records[iterator]
            if len(record) > 1:
                records.append(record)

        return records

    def _get_sqlite_records(self, fh, path):
        db = sqlite3.SQLite3(fh)
        if (sqlite_db_wal := self.target.fs.path(str(path) + "-wal")).exists():
            print(type(sqlite_db_wal.open()))
            db.open_wal(sqlite_db_wal.open())

        gather_file = self.target.fs.path("sysvol/programdata/microsoft/search/data/applications/windows/Windows-gather.db")
        gather_db = sqlite3.SQLite3(gather_file.open("rb"))
        if (gather_db_wal := self.target.fs.path(str(gather_file) + "-wal")).exists():
            gather_db.open_wal(gather_db_wal.open())
        
        # pa = db.pages()
        # for p in pa:
        #     print(p)
        #     for x in p.cells():
        #         print(x)
        #         try:
        #             print(x.values)
        #         except :
        #             print("no cell data")
        #         input()

        fr = db.wal.frames()
        print(db.wal.header.checkpoint_sequence_number)
        for f in fr:
            print(f.header)
            print(f)
            #print(f)
        input()

        ch = db.wal.checkpoints()
        for c in ch:
            print(c)
            for f in c.frames:
                print(f)
                print(f.page_number)
                page =db.page(f.page_number)
                print(page)
                for c in page.cells():
                    print(c.values)
                input()
        input()


        gthr_table_rows = sorted(list(gather_db.table("SystemIndex_Gthr")), key=lambda x: x["DocumentID"])
        propstore_table_rows = sorted(list(db.table("SystemIndex_1_PropertyStore")), key=lambda x: x["WorkId"])
        propstore_table_metadata = list(db.table("SystemIndex_1_PropertyStore_Metadata"))

        self.propstore_metadata = []
        for row in propstore_table_metadata:
            if "-" in row["Name"]:
                column_name = row["Name"].split("-")[1]
            else:
                column_name = row["Name"]
            self.propstore_metadata.append({
                "Id": row['Id'],
                "Name": column_name
            })

        gthr_records = {}

        for row in gthr_table_rows:
            if (last_modified := row["LastModified"]) is not None:
                last_modified = wintimestamp(int.from_bytes(last_modified, "little"))
            gthr_records[row['DocumentID']] = {
                "FileName": row["FileName"],
                "LastModified":  last_modified,
                "SDID": row["SDID"],
            }

        propstore_records = {}

        merged_propstore_rows = {}
        for row in propstore_table_rows:
            work_id = row['WorkId']
            if work_id not in merged_propstore_rows:
                merged_propstore_rows[work_id] = [row]
            else:
                merged_propstore_rows[work_id].append(row)
        for work_id, row_list in merged_propstore_rows.items():
            merged_object = {}
            for row in row_list:
                col_id = row['ColumnId']
                col_name = self._get_sqlite_column_name_propstore(col_id)
                value = row['Value']
                if col_name in WIN_DATETIME_FIELDS and value is not None:
                    try:
                        value = wintimestamp(int.from_bytes(value, "little"))
                    except ValueError:
                        value = None
                merged_object[col_name] = value
            propstore_records[work_id] = merged_object

        records = []
        last_gthr_id = list(gthr_records.keys())[-1]
        last_propstore_id = list(propstore_records.keys())[-1]
        for iterator in range(0, (last_gthr_id if last_gthr_id > last_propstore_id else last_propstore_id)):
            record = {"WorkID": iterator}
            if iterator in gthr_records:
                record = record | gthr_records[iterator]
            if iterator in propstore_records:
                record = record | propstore_records[iterator]
            if len(record) > 1:
                records.append(record)

        return records

    @export(record=SearchIndexFileInfoRecord)
    def searchindex(self):
        """X"""
        for path in self._files:
            fh = path.open("rb")

            if path.name.endswith(".edb"):
                records = self._get_edb_records(fh)

            else:
                records = self._get_sqlite_records(fh, path)

            for record in records:
                if (systemitemtype := record.get("System_ItemType")) == "ActivityHistoryItem":
                    yield SearchIndexFileActivityRecord(
                        starttime=record.get("System_ActivityHistory_StartTime"),
                        endtime=record.get("System_ActivityHistory_EndTime"),
                        appid=record.get("System_ActivityHistory_AppId"),
                        file_contenturi=record.get("System_Activity_ContentUri"),
                        description=record.get("System_Activity_Description"),
                        displaytext=record.get("System_Activity_DisplayText"),
                        itempathdisplay=record.get("System_ItemPathDisplay"),
                        systemitemtype=systemitemtype,
                    )
                else:
                    if not (filename := record.get("System_ItemPathDisplay")) is None:
                        filename = filename.replace("\\", "/")
                    if not (autosummary := record.get("System_Search_AutoSummary")) is None:
                        autosummary = autosummary.encode("utf-8").hex()
                    if not (fileattributes := record.get("System_FileAttributes")) is None:
                        fileattributes = str(c_ntfs.FILE_ATTRIBUTE(fileattributes)).replace("FILE_ATTRIBUTE.", "")
                    yield SearchIndexFileInfoRecord(
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
                    )
                
                

                # for record in propstore_table_rows:
                #     print(record)
                # input()
                # not_in_gthr = []
                # not_in_propstore = []
                # for gthr_record in gthr_records:
                #     record = {}
                #     doc_id = gthr_record.get("DocumentID")
                    
                #     while doc_id > propstore_table_rows[propstore_index].get("WorkId"):
                #         #print(propstore_table_rows[propstore_index])
                #         not_in_gthr.append(propstore_table_rows[propstore_index])
                #         #print("FIXING", doc_id, propstore_table_rows[propstore_index].get("WorkId"))
                #         propstore_index += 1
                        
                #     if doc_id < propstore_table_rows[propstore_index].get("WorkId"):
                #         print("mismatch continueing")
                #         not_in_propstore.append(gthr_record)
                #         continue
                #     # print("DOCID", doc_id)
                #     # print("WORKID", propstore_table_rows[propstore_index].get("WorkId"))
                #     # print(propstore_table_rows[propstore_index])
                #     # print(propstore_index)
                #     while propstore_table_rows[propstore_index].get("WorkId") == doc_id:
                #         column_name = self._get_column_name_propstore_sqlite(propstore_table_rows[propstore_index].get("ColumnId"))
                #         if column_name in PROPSTORE_INCLUDE_COLUMNS:
                #             value = propstore_table_rows[propstore_index].get("Value")
                #             if column_name in WIN_DATETIME_FIELDS and value is not None:
                #                 try:
                #                     value = wintimestamp(int.from_bytes(value, WIN_DATETIME_FIELDS[column_name]))
                #                 except ValueError:
                #                     value = None
                #             record[column_name] = value

                #         propstore_index += 1
                #         if propstore_index == len(propstore_table_rows):
                #             break
                #     record["WorkID"] = doc_id
                #     propstore_records.append(record)
                #     # print(record)
                # print(len(propstore_records))
                # print(len(propstore_table_rows))
                # print(len(not_in_gthr))
                # print(len(not_in_propstore))
                # for i in not_in_gthr:
                #     print(i)
                # input()
                # for i in not_in_propstore:
                #     print(i)
                # input()




                
                # for row in gthr_records:
                #     record = {}
                #     record['WorkID'] = row['DocumentID']
                #     propstore_rows = [p for p in propstore_table_rows if p['WorkId'] == row["DocumentID"]]
                #     for column_name in PROPSTORE_INCLUDE_COLUMNS[1:]:
                #         value = self._get_value_propstore_sqlite(propstore_rows, column_name)
                #         record[column_name] = value
                #     #print(record)
                #     propstore_records.append(record)
