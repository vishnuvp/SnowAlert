import yaml from 'js-yaml';

import {BaselinePayload} from '../reducers/types';

export class Baseline {
  raw: BaselinePayload;
  metadata: {
    data_source: string;
    time_column: string;
    days_cutoff: number;
    module: string;
    interpolated_values: any;
  };

  constructor(bl: BaselinePayload) {
    this.raw = bl;
    this.metadata = yaml.safeLoad(bl.comment);
  }
  get tableName() {
    return this.raw.table_name;
  }

  get title() {
    let title = this.raw.table_name || 'title missing';
    return title.replace(/_/g, ' ');
  }

  get description() {
    return 'parsed description goes here';
  }

  get comment() {
    return yaml.safeDump(this.metadata);
  }

  get rowCount() {
    return this.raw.rows;
  }

  get dataSource() {
    return this.metadata.data_source;
  }

  get timeColumn() {
    return this.metadata.time_column;
  }
  get daysCutoff() {
    return this.metadata.days_cutoff;
  }
  get module() {
    return this.metadata.module;
  }
  get interpolatedValues() {
    return this.metadata.interpolated_values;
  }
}
