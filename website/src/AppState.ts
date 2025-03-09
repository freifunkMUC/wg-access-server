import { observable, makeObservable, runInAction } from 'mobx';
import { InfoRes } from './sdk/server_pb';

class GlobalAppState {
  info?: InfoRes.AsObject;
  loadingError?: String;
  darkMode: boolean;

  constructor() {
    makeObservable(this, {
      info: observable,
      darkMode: observable,
      loadingError: observable,
    });

    this.darkMode = false;
  }

  setDarkMode(darkMode: boolean) {
    runInAction(() => {
      this.darkMode = darkMode;
    });
  }

  setInfo(info: InfoRes.AsObject){
    runInAction(() => {
      this.info = info;
    });
  }
}

export const AppState = new GlobalAppState();

console.info('see global app state by typing "window.AppState"');

Object.assign(window as any, {
  get AppState() {
    return JSON.parse(JSON.stringify(AppState));
  },
});
