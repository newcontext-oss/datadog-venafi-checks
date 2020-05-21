# stdlib
from datetime import datetime
from pathlib import Path
from os.path import getmtime

# 3rd party
import requests

# project
from datadog_checks.checks import AgentCheck


class VenafiDB(AgentCheck):
    BACKUP_PATH = ""

    def check(self, instance):
        if "backup_path" not in instance:
            raise Exception('Venafi instance missing "backup_path" value.')

        self.BACKUP_PATH = instance["backup_path"]

        self.check_backup_mtime()

    def get_backup_mtime(self):
        path = Path(self.BACKUP_PATH)

        if path.exists():
            mtime_epoch = getmtime(path)
            mtime = datetime.fromtimestamp(mtime_epoch).strftime("%Y-%m-%d-%H:%M")

            return mtime

        return None

    def check_backup_mtime(self):
        mtime = self.get_backup_mtime()

        if mtime:
            self.service_check(
                "venafi.db_backup.mtime",
                AgentCheck.OK,
                message="Found backup mtime at %s" % mtime,
                tags=["mtime:%s" % mtime],
            )
        else:
            self.service_check(
                "venafi.db_backup.mtime",
                AgentCheck.UNKNOWN,
                message="DB Backup not found at: " % self.DB_BACKUP_PATH,
                tags=[],
            )
