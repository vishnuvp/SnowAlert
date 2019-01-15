#!/usr/local/bin/python
import csv
import sys
import logging
import os
from runners.helpers import db

def query_snowflake(query):
    global writer
    finished = False
    offset = 0
    limit = 10000000
    while(not finished):
        num_results = 0
        conn = db.connect()
        #conn.cursor().execute("USE WAREHOUSE SNOWHOUSE;")
        query_with_limit = query + " limit %s offset %s" % (limit, offset)
        data = db.fetch(conn, query_with_limit)
        for row in data:
            num_results += 1
            if writer is None:
                writer = csv.DictWriter(sys.stdout , row.keys())
                writer.writeheader()
            writer.writerow(row)
        if(num_results < limit):
            finished = True
        offset += limit


writer=None
query_snowflake("SELECT city, state, ip_address, login_status, user_id, event_time, date_trunc('DAY' ,event_time) as DAY from security.prod.azure_ad_signin_v where event_time > dateadd(day, -365, current_timestamp)")
