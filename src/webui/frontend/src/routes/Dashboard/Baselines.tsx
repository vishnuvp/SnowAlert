import {
  // Avatar,
  // Button,
  Card,
  Icon,
  // Input,
  // List,
  // Modal,
  // Select
} from 'antd';
import React from 'react';
import {connect} from 'react-redux';
import {bindActionCreators, Dispatch} from 'redux';
import {getData} from '../../reducers/data';
import * as stateTypes from '../../reducers/types';
import {
  loadSAData,
  newConnection,
  // selectBaseline,
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
  newConnection: typeof newConnection;
  finalizeConnection: typeof finalizeConnection;
  testConnection: typeof testConnection;
  // selectBaseline: typeof selectBaseline;
  dismissErrorMessage: typeof dismissErrorMessage;
}

type BaselinesProps = StateProps & DispatchProps;

class Baselines extends React.Component<BaselinesProps, OwnState> {
  constructor(props: any) {
    super(props);

    this.state = {
      optionValues: {},
    };

    // if (this.findBaseline()) {
    //   this.selectBaseline(null);
    // }
  }

  componentDidMount() {
    this.props.loadSAData();
  }

  // selectBaseline(name: string | null) {
  //   const selectedBaseline = this.findBaseline(name);
  //   if (selectedBaseline) {
  //     const entries = [['name', 'default'], ...selectedBaseline.options.map((o: any) => [o.name, o.default])];
  //     this.setState({
  //       optionValues: Object.fromEntries(entries),
  //     });
  //   }
  //   this.props.selectBaseline(name);
  // }

  findBaseline(title: string | null = null) {
    const {baselines, selected} = this.props.data;
    const toFind = title || selected;
    return baselines.find(b => b.title === toFind);
  }

  changeOption(name: string, value: string) {
    const {optionValues} = this.state;
    this.setState({
      optionValues: Object.assign({}, optionValues, {[name]: value}),
    });
  }

  render() {
    const {
      baselines,
      // connectionStage,
      // connectionMessage,
      // errorMessage,
    } = this.props.data;

    // const {optionValues} = this.state;

    const selectedBaseline = this.findBaseline();

    // let options: any[] = [];
    // if (selectedBaseline) {
    //   options = [
    //     ...selectedBaseline.options,
    //     {
    //       name: 'name',
    //       title: 'Custom Name (optional)',
    //       prompt: 'If you are configuring multiple connections of this type, enter a custom name for this one',
    //       default: 'default',
    //       required: true,
    //       disabled: connectionStage !== 'start',
    //     },
    //   ];
    // }

    return selectedBaseline ? (
      <div>{selectedBaseline.title} selected</div>
    ) : (
      <div>
        {baselines.map(b => (
          <Card
            key={b.title}
            style={{width: 350, margin: 10, float: 'left'}}
            actions={[
              // <a key={1} onClick={() => this.selectBaseline(b.title)}>
              <a key={1} onClick={() => console.log(b.title)}>
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
      // selectBaseline,
      finalizeConnection,
      testConnection,
      newConnection,
    },
    dispatch,
  );
};

export default connect<StateProps, DispatchProps>(
  mapStateToProps,
  mapDispatchToProps,
)(Baselines);
