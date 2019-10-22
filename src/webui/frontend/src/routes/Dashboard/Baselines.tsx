import {Button, Card, Icon, Input, List, Select} from 'antd';
import React from 'react';
import {connect} from 'react-redux';
import {bindActionCreators, Dispatch} from 'redux';
import {getData} from '../../reducers/data';
import * as stateTypes from '../../reducers/types';
import {
  loadSAData,
  createBaseline,
  selectBaseline,
  finalizeConnection,
  testConnection,
  dismissErrorMessage,
} from '../../actions/data';

import './Baselines.css';

interface OwnState {
  optionValues: any;
}

interface StateProps {
  data: stateTypes.SADataState;
}

interface DispatchProps {
  loadSAData: typeof loadSAData;
  createBaseline: typeof createBaseline;
  finalizeConnection: typeof finalizeConnection;
  testConnection: typeof testConnection;
  selectBaseline: typeof selectBaseline;
  dismissErrorMessage: typeof dismissErrorMessage;
}

type BaselinesProps = StateProps & DispatchProps;

class Baselines extends React.Component<BaselinesProps, OwnState> {
  constructor(props: any) {
    super(props);

    this.state = {
      optionValues: {},
    };
  }

  componentDidMount() {
    this.props.loadSAData();
  }

  findBaseline(title: string | null = null) {
    const {baselines, selected} = this.props.data;
    const toFind = title || selected;
    return baselines.find(b => b.baseline === toFind);
  }

  changeOption(name: string, value: string) {
    const {optionValues} = this.state;
    this.setState({
      optionValues: Object.assign({}, optionValues, {[name]: value}),
    });
  }

  render() {
    const {baselines} = this.props.data;

    const {optionValues} = this.state;

    const selectedBaseline = this.findBaseline();

    let options: any[] = [];
    if (selectedBaseline) {
      options = [
        {
          name: 'base_table',
          title: 'Base Table',
          prompt: 'Table with the data we will be baselining',
          default: 'data.',
          required: true,
        },
        ...selectedBaseline.options,
      ];
    }

    return selectedBaseline ? (
      <div>
        <h1>Creating {selectedBaseline.title}</h1>
        <List
          itemLayout="vertical"
          size="small"
          grid={{gutter: 0}}
          dataSource={options}
          renderItem={(opt: any) => (
            <List.Item key={opt.name}>
              <label>
                <List.Item.Meta title={opt.title || opt.name.replace('_', ' ')} description={opt.prompt} />

                {opt.options ? (
                  <Select
                    defaultValue={opt.placeholder || opt.default || '- pick one -'}
                    dropdownMatchSelectWidth={false}
                    onChange={(v: any) => {
                      this.changeOption(opt.name, v);
                    }}
                  >
                    {opt.options.map((o: any) => (
                      <Select.Option key={o.value} value={o.value}>
                        {o.label}
                      </Select.Option>
                    ))}
                  </Select>
                ) : (
                  React.createElement(opt.secret || opt.mask_on_screen ? Input.Password : Input, {
                    name: opt.name,
                    defaultValue: opt.default,
                    addonBefore: opt.prefix,
                    addonAfter: opt.postfix,
                    placeholder: opt.placeholder,
                    autoComplete: 'off',
                    onBlur: (e: any) => {
                      if (opt.required && opt.default && e.target.value === '') {
                        this.changeOption(opt.name, opt.default);
                      }
                    },
                    onChange: (e: any) => {
                      // todo why doesn't ref to e work here w/ prevState?
                      this.changeOption(opt.name, e.target.value);
                    },
                  })
                )}
              </label>
            </List.Item>
          )}
        />
        <Button
          onClick={() => {
            this.props.selectBaseline(null);
          }}
        >
          &larr; Go Back
        </Button>

        <Button
          style={{float: 'right'}}
          onClick={() => {
            this.props.createBaseline(selectedBaseline.baseline, optionValues);
          }}
        >
          {'Create'}
        </Button>
      </div>
    ) : (
      <div>
        {baselines.map(b => (
          <Card
            key={b.baseline}
            style={{width: 350, margin: 10, float: 'left'}}
            actions={[
              <a key={1} onClick={() => this.props.selectBaseline(b.baseline)}>
                <Icon type="line-chart" /> Construct
              </a>,
            ]}
          >
            <Card.Meta
              avatar={
                null
                // <Avatar src={`/icons/baselines/${b.title}.png`} />
              }
              title={b.title}
              description={b.description}
              style={{height: 75}}
            />
          </Card>
        ))}
      </div>
    );
  }
}

const mapStateToProps = (state: stateTypes.State) => {
  return {
    data: getData(state),
  };
};

const mapDispatchToProps = (dispatch: Dispatch) => {
  return bindActionCreators(
    {
      dismissErrorMessage,
      loadSAData,
      selectBaseline,
      finalizeConnection,
      testConnection,
      createBaseline,
    },
    dispatch,
  );
};

export default connect<StateProps, DispatchProps>(
  mapStateToProps,
  mapDispatchToProps,
)(Baselines);
