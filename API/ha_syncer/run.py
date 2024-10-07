import os
import sys

import django
from django.db import connections

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api.settings")

django.setup()
db_conn = connections['default']

from ha_syncer.config import HASyncWatcher

HASyncWatcher(interval=10)
