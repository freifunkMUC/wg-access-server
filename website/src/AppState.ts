import { observable, makeObservable, runInAction } from 'mobx';
import { InfoRes } from './sdk/server_pb';

class GlobalAppState {
  info?: InfoRes.AsObject;
  loadingError?: String;
  darkMode: boolean;
  refreshDevices?: () => void;

  constructor() {
    makeObservable(this, {
      info: observable,
      darkMode: observable,
      loadingError: observable,
      refreshDevices: observable,
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

  setRefreshDevices(refreshFn: () => void) {
    runInAction(() => {
      this.refreshDevices = refreshFn;
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
