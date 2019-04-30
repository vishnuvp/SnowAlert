import {
  // Badge,
  Button,
  Card,
  Divider,
  Icon,
  // Input,
  List,
  // Table,
  Row,
} from 'antd';
import React from 'react';
import {connect} from 'react-redux';
import {bindActionCreators, Dispatch} from 'redux';
import '../../index.css';

import {getData} from '../../reducers/data';
import * as stateTypes from '../../reducers/types';
import {Baseline} from '../../store/data';
import {
  makeBaseline,
  // revertBaseline,
  // saveBaseline,
  // deleteBaseline,
  // updateBaselineTitle,
  // updateBaselineDescription,
  changeBaselineSelection,
  loadSAData,
} from '../../actions/data';
import './Baselines.css';

interface StateProps {
  data: stateTypes.SADataState;
}

interface DispatchProps {
  makeBaseline: typeof makeBaseline;
  // revertBaseline: typeof revertBaseline;
  // saveBaseline: typeof saveBaseline;
  // deleteBaseline: typeof deleteBaseline;
  // updateBaselineTitle: typeof updateBaselineTitle;
  // updateBaselineDescription: typeof updateBaselineDescription;
  changeBaselineSelection: typeof changeBaselineSelection;
  loadSAData: typeof loadSAData;
}

class Baselines extends React.PureComponent<StateProps & DispatchProps> {
  componentDidMount() {
    this.props.loadSAData();
    this.props.changeBaselineSelection(null);
  }

  render() {
    const {
      changeBaselineSelection,
      data: {baselines},
    } = this.props;

    const {
      data: {selected},
    } = this.props;

    // <Badge
    //   count={`${policy.subpolicies.filter(x => x.passing).length}`}
    //   style={{color: '#52c41a', backgroundColor: '#eafbe1', marginRight: 10}}
    // />
    // <Badge
    //   count={`${policy.subpolicies.filter(x => x.passing === false).length}`}
    //   style={{color: '#ff3434', backgroundColor: '#ffe5e5', marginRight: 10}}
    // />
    // {policy.isEditing ? (
    //   <Input
    //     value={policy.title}
    //     style={{width: 500}}
    //     onChange={e => this.props.updateBaselineTitle(policy.viewName, e.currentTarget.value)}
    //   />
    // ) : (
    //   <a
    //     onClick={() =>
    //       this.props.changeRule(policy.viewName === currentRuleView ? '' : policy.viewName)
    //     }
    //   >
    //     {policy.title}
    //   </a>
    // )}
    // {policy.viewName === currentRuleView &&
    //   (policy.isEditing ? (
    //     <span style={{float: 'right'}}>
    //       <Button
    //         type="primary"
    //         disabled={policy.isSaving || !policy.isEdited}
    //         style={{marginRight: 10}}
    //         onClick={() => this.props.saveRule(Object.assign(policy.raw, {body: policy.body}))}
    //       >
    //         {policy.isSaving ? <Icon type="loading" theme="outlined" /> : 'Save'}
    //       </Button>
    //       <Button type="default" disabled={false} onClick={() => this.props.revertRule(policy)}>
    //         Cancel
    //       </Button>
    //     </span>
    //   ) : (
    //     <Button onClick={() => this.props.editRule(policy.viewName)} style={{float: 'right'}}>
    //       <Icon type="edit" /> edit
    //     </Button>
    //   ))}

    // {policy.viewName === currentRuleView && (
    //   <Table
    //     pagination={false}
    //     columns={[
    //       {title: '', dataIndex: 'passing', key: 'passing', width: 5, render: successDot},
    //       {
    //         title: 'Title',
    //         dataIndex: 'title',
    //         key: 'title',
    //         render: (text, record, i) =>
    //           policy.isEditing ? (
    //             <Input.TextArea
    //               disabled={policy.isSaving}
    //               autosize={{minRows: 1, maxRows: 1}}
    //               value={text}
    //               onChange={e => this.props.editSubpolicy(policy.viewName, i, {title: e.target.value})}
    //             />
    //           ) : (
    //             text
    //           ),
    //       },
    //       {
    //         title: 'Condition',
    //         dataIndex: 'condition',
    //         key: 'condition',
    //         render: (text, record, i) =>
    //           policy.isEditing ? (
    //             <Input.TextArea
    //               disabled={policy.isSaving}
    //               autosize={{minRows: 1, maxRows: 1}}
    //               value={text}
    //               onChange={e =>
    //                 this.props.editSubpolicy(policy.viewName, i, {condition: e.target.value})
    //               }
    //             />
    //           ) : (
    //             text
    //           ),
    //       },
    //       {
    //         title: 'Actions',
    //         render: (text, record, i) =>
    //           policy.isEditing ? (
    //             <div>
    //               <Button
    //                 type="danger"
    //                 disabled={policy.subpolicies.length < 2}
    //                 onClick={() => this.props.deleteSubpolicy(policy.viewName, i)}
    //               >
    //                 <Icon type="delete" />
    //               </Button>
    //             </div>
    //           ) : (
    //             <div />
    //           ),
    //       },
    //     ]}
    //     dataSource={policy.subpolicies}
    //     rowKey={'i'}
    //   />
    // )}

    return (
      <Card
        extra={
          <Button onClick={() => this.props.makeBaseline()}>
            <Icon type="line-chart" /> new baseline
          </Button>
        }
      >
        <Card.Meta
          title="Baselines"
          description={`
            A Baseline is a computed set of data that takes longer to create
            than Alert Queries allow.
          `}
        />
        <Divider />
        <Row>
          <List
            itemLayout="vertical"
            dataSource={baselines}
            renderItem={(baseline: Baseline) => (
              <List.Item>
                <List.Item.Meta
                  title={
                    <span onClick={() => changeBaselineSelection(baseline.tableName)}>
                      {selected == baseline.tableName ? '*' : ''}
                      {baseline.title}
                    </span>
                  }
                  description={baseline.description}
                />
                <div>{baseline.comment}</div>
              </List.Item>
            )}
          />
        </Row>
      </Card>
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
      makeBaseline,
      // revertBaseline,
      // saveBaseline,
      // deleteBaseline,
      // updateBaselineTitle,
      // updateBaselineDescription,
      changeBaselineSelection,
      loadSAData,
    },
    dispatch,
  );
};

export default connect<StateProps, DispatchProps>(
  mapStateToProps,
  mapDispatchToProps,
)(Baselines);
