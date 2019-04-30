import {Reducer} from 'redux';
import {
  DataActions,
  LOAD_SA_DATA_REQUEST,
  LOAD_SA_DATA_SUCCESS,
  LOAD_SA_DATA_FAILURE,
  CHANGE_BASELINE_SELECTION,
} from '../actions/data';
import {
  // SAData,
  SADataState,
  State,
} from './types';
import {Baseline} from '../store/data';

export const initialState: SADataState = {
  isFetching: false,
  selected: null,
  baselines: [],
};

export const data: Reducer<SADataState> = (state = initialState, action: DataActions) => {
  switch (action.type) {
    case CHANGE_BASELINE_SELECTION: {
      return {
        ...state,
        baselines: state.baselines.map(bl =>
          bl.tableName === state.selected ? Object.assign(bl, {isEditing: true}) : bl,
        ),
        isFetching: true,
      };
    }
    case LOAD_SA_DATA_REQUEST: {
      return {
        ...state,
        isFetching: true,
      };
    }
    case LOAD_SA_DATA_FAILURE: {
      return {
        ...state,
        isFetching: false,
      };
    }
    case LOAD_SA_DATA_SUCCESS: {
      let {baselines} = action.payload;
      return {
        ...state,
        isFetching: false,
        baselines: baselines.map(b => new Baseline(b)),
      };
    }
  }
  return state;
};

export const getData = (state: State) => {
  return state.data;
};
