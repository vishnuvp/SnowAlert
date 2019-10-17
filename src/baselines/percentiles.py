"""Basic Baseline

Compare the count of events in a window to percentiles of counts in prior windows.
"""

from typing import List

from runners.helpers import db

OPTIONS = [
    {
        'name': 'window_size',
        'title': "Window Size",
        'prompt': "Length of time count and compare (e.g. 24h, 7d)",
        'type': 'text',
        'default': "24h",
        'required': True,
    },
    {
        'name': 'history_size',
        'title': "History Size",
        'prompt': "Days to calc percentiles of (e.g. 30)",
        'type': 'text',
        'default': "30",
        'required': True,
    },
    # {
    #     'name': 'drop_zeros',
    #     'title': "Drop Zeros",
    #     'prompt': "Ignore empty windows when calculating percentiles",
    #     'type': 'bool',
    #     'default': "30d",
    #     'required': True,
    # },
]

COUNT_HOURLY_TABLE_SQL = """
CREATE OR REPLACE TABLE {base_table}_count_hourly (
  slice_start timestamp_ltz,
  slice_end timestamp_ltz,
  groups variant,
  n number
)
;
"""

COUNT_HOURLY_MERGE_SQL = """
MERGE INTO {base_table}_count_hourly stored
USING (
  -- calculate sums
  SELECT COUNT(*) n
       , slice_start
       , slice_end
       , groups
  FROM (
    -- find slices that are missing data
    SELECT slice_start, slice_end
    FROM TABLE(data.TIME_SLICES_BEFORE_T(
      {days}*24, 60*60, DATE_TRUNC(HOUR, CURRENT_TIMESTAMP)
    ))
    LEFT JOIN {base_table}_count_hourly
    USING (slice_start, slice_end)
    WHERE n IS NULL
  ) t
  JOIN (
    -- calculate sums in those slices
    SELECT event_time
         , OBJECT_CONSTRUCT(
             {groups}
           ) AS groups
    FROM {base_table}
  ) c
  ON c.event_time BETWEEN t.slice_start AND t.slice_end
  GROUP BY slice_start, slice_end, groups
) calcd
ON (
  stored.groups = calcd.groups
  AND stored.slice_start = calcd.slice_start
  AND stored.slice_end = calcd.slice_end
)
WHEN NOT MATCHED THEN INSERT (
  slice_start,
  slice_end,
  groups,
  n
)
VALUES (
  slice_start,
  slice_end,
  groups,
  n
)
"""

COUNT_HOURLY_TASK_SQL = f"""
CREATE OR REPLACE TASK {{base_table}}_count_hourly
  SCHEDULE='USING CRON 0 * * * * UTC'
  WAREHOUSE=snowalert_warehouse
AS
{COUNT_HOURLY_MERGE_SQL}
"""

BASIC_BASELINE_VIEW = """
CREATE OR REPLACE VIEW {base_table}_pct_baseline AS
SELECT * FROM (
  SELECT slice_start hour
       , groups
       , count_24h n
       , APPROX_PERCENTILE(n, .01) OVER (PARTITION BY groups) AS pct01
       , APPROX_PERCENTILE(n, .05) OVER (PARTITION BY groups) AS pct05
       , APPROX_PERCENTILE(n, .10) OVER (PARTITION BY groups) AS pct10
       , APPROX_PERCENTILE(n, .90) OVER (PARTITION BY groups) AS pct90
       , APPROX_PERCENTILE(n, .95) OVER (PARTITION BY groups) AS pct95
       , APPROX_PERCENTILE(n, .99) OVER (PARTITION BY groups) AS pct99
  FROM (
    SELECT SUM(n) OVER (
             PARTITION BY groups
             ORDER BY slice_start
             ROWS BETWEEN 24 PRECEDING
                      AND 1 PRECEDING
           ) count_24h
         , slice_start
         , groups
    FROM (
      -- zero-filled count table
      SELECT ZEROIFNULL(n) n
           , groups
           , slice_start
           , slice_end
      FROM {base_table}_count_hourly
      RIGHT JOIN (
        -- zero filled matrix of (groups X slices)
        SELECT groups, slice_start, slice_end
        FROM (
          SELECT DISTINCT groups FROM {base_table}_count_hourly
        ) g
        CROSS JOIN (
          SELECT slice_start, slice_end
          FROM TABLE(TIME_SLICES_BEFORE_T(
            {days}*24, 60*60, DATE_TRUNC(HOUR, CURRENT_TIMESTAMP)
          ))
        ) t
      )
      USING (groups, slice_start, slice_end)
    )
    WHERE slice_start > DATEADD(HOUR, -24 * ({days} + 1), DATE_TRUNC(HOUR, CURRENT_TIMESTAMP))
  )
  WHERE count_24h IS NOT NULL
  ORDER BY slice_start DESC
)
WHERE hour = (
  SELECT MAX(slice_start)
  FROM {base_table}_count_hourly
)
ORDER BY n DESC
"""


def generate_baseline_sql(
    base_table: str, groups: List[str], days: int = 30
) -> List[str]:
    groups_sql = (',\n' + ' ' * 13).join(f"'{g}', {g}" for g in groups)
    return [
        'SELECT CURRENT_USER()',
        'SELECT CURRENT_ROLE()',
        COUNT_HOURLY_TABLE_SQL.format(base_table=base_table),
        # COUNT_HOURLY_MERGE_SQL.format(base_table=base_table, groups=groups_sql, days=days),
        COUNT_HOURLY_TASK_SQL.format(base_table=base_table, groups=groups_sql, days=days),
        f'ALTER TASK {base_table}_count_hourly RESUME',
        BASIC_BASELINE_VIEW.format(base_table=base_table, days=days),
    ]


def create(options):
    base_table = options['base_table']
    groups = options.get('groups', '').split('\n')
    days = int(options.get('days', '0'))
    for sql in generate_baseline_sql(base_table, groups, days):
        print(next(db.fetch(sql)))
