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

    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const storedDarkMode = localStorage.getItem('customDarkMode');

    this.darkMode = storedDarkMode !== null ? JSON.parse(storedDarkMode) : prefersDarkMode;
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

  setLoadingError(error: String){
    runInAction(() => {
      this.loadingError = error;
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
