import {Dispatch} from 'redux';
import * as api from '../api';
import {BaselinePayload, State} from '../reducers/types';
import {createAction, ActionWithPayload, GetState} from './action-helpers';
import {ActionsUnion} from './types';

//
// Baselines
//

// load rules
export const LOAD_SA_DATA_REQUEST = 'LOAD_SA_DATA_REQUEST';
export const LOAD_SA_DATA_SUCCESS = 'LOAD_SA_DATA_SUCCESS';
export const LOAD_SA_DATA_FAILURE = 'LOAD_SA_DATA_FAILURE';

export type LoadDataPayload = {
  baselines: ReadonlyArray<BaselinePayload>;
};

export const LoadDataActions = {
  loadDataRequest: () => createAction(LOAD_SA_DATA_REQUEST),
  loadDataSuccess: (response: LoadDataPayload) => createAction(LOAD_SA_DATA_SUCCESS, response),
  loadDataFailure: (errorMessage: string) => createAction(LOAD_SA_DATA_FAILURE, errorMessage),
};

type LoadDataActions = ActionsUnion<typeof LoadDataActions>;

const shouldLoadData = (state: State) => {
  const data = state.data;
  return !data.isFetching && !data.baselines.length;
};

export const loadSAData = () => async (dispatch: Dispatch, getState: GetState) => {
  const state = getState();
  console.log('state', state, state.data.isFetching, state.data.baselines.length);
  if (shouldLoadData(state)) {
    dispatch(LoadDataActions.loadDataRequest());
    try {
      const response = await api.loadSnowAlertData();
      dispatch(LoadDataActions.loadDataSuccess(response));
    } catch (error) {
      dispatch(LoadDataActions.loadDataFailure(error.message));
    }
  }
};

export const MAKE_BASELINE = 'MAKE_BASELINE';
export const makeBaseline = () => async (dispatch: Dispatch) => {};

export const SAVE_BASELINE = 'SAVE_BASELINE';
export const REVERT_BASELINE = 'REVERT_BASELINE';
export const DELETE_BASELINE = 'DELETE_BASELINE';

export const UPDATE_BASELINE_TITLE = 'UPDATE_BASELINE_TITLE';
export const UPDATE_BASELINE_DESCRIPTION = 'UPDATE_BASELINE_DESCRIPTION';

export const CHANGE_BASELINE_SELECTION = 'CHANGE_BASELINE_SELECTION';
type ChangeBaselineSelectionAction = ActionWithPayload<typeof CHANGE_BASELINE_SELECTION, string>;
export const changeBaselineSelection = (bl_name: string | null) => async (dispatch: Dispatch) => {
  dispatch(createAction(CHANGE_BASELINE_SELECTION, bl_name));
};

export type DataActions = LoadDataActions | ChangeBaselineSelectionAction;
