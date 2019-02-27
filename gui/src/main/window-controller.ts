import { BrowserWindow, Display, screen, Tray, WebContents } from 'electron';

interface IPosition {
  x: number;
  y: number;
}

export interface IWindowShapeParameters {
  arrowPosition?: number;
}

interface IWindowPositioning {
  getPosition(window: BrowserWindow): IPosition;
  getWindowShapeParameters(window: BrowserWindow): IWindowShapeParameters;
}

class StandaloneWindowPositioning implements IWindowPositioning {
  public getPosition(window: BrowserWindow): IPosition {
    const windowBounds = window.getBounds();

    const primaryDisplay = screen.getPrimaryDisplay();
    const workArea = primaryDisplay.workArea;
    const maxX = workArea.x + workArea.width - windowBounds.width;
    const maxY = workArea.y + workArea.height - windowBounds.height;

    const x = Math.min(Math.max(windowBounds.x, workArea.x), maxX);
    const y = Math.min(Math.max(windowBounds.y, workArea.y), maxY);

    return { x, y };
  }

  public getWindowShapeParameters(_window: BrowserWindow): IWindowShapeParameters {
    return {};
  }
}

class AttachedToTrayWindowPositioning implements IWindowPositioning {
  private tray: Tray;

  constructor(tray: Tray) {
    this.tray = tray;
  }

  public getPosition(window: BrowserWindow): IPosition {
    const windowBounds = window.getBounds();
    const trayBounds = this.tray.getBounds();

    const activeDisplay = screen.getDisplayNearestPoint({
      x: trayBounds.x,
      y: trayBounds.y,
    });
    const workArea = activeDisplay.workArea;
    const placement = this.getTrayPlacement();
    const maxX = workArea.x + workArea.width - windowBounds.width;
    const maxY = workArea.y + workArea.height - windowBounds.height;

    let x = 0;
    let y = 0;

    switch (placement) {
      case 'top':
        x = trayBounds.x + (trayBounds.width - windowBounds.width) * 0.5;
        y = workArea.y;
        break;

      case 'bottom':
        x = trayBounds.x + (trayBounds.width - windowBounds.width) * 0.5;
        y = workArea.y + workArea.height - windowBounds.height;
        break;

      case 'left':
        x = workArea.x;
        y = trayBounds.y + (trayBounds.height - windowBounds.height) * 0.5;
        break;

      case 'right':
        x = workArea.width - windowBounds.width;
        y = trayBounds.y + (trayBounds.height - windowBounds.height) * 0.5;
        break;

      case 'none':
        x = workArea.x + (workArea.width - windowBounds.width) * 0.5;
        y = workArea.y + (workArea.height - windowBounds.height) * 0.5;
        break;
    }

    x = Math.min(Math.max(x, workArea.x), maxX);
    y = Math.min(Math.max(y, workArea.y), maxY);

    return {
      x: Math.round(x),
      y: Math.round(y),
    };
  }

  public getWindowShapeParameters(window: BrowserWindow): IWindowShapeParameters {
    const trayBounds = this.tray.getBounds();
    const windowBounds = window.getBounds();
    const arrowPosition = trayBounds.x - windowBounds.x + trayBounds.width * 0.5;
    return {
      arrowPosition,
    };
  }

  private getTrayPlacement() {
    switch (process.platform) {
      case 'darwin':
        // macOS has menubar always placed at the top
        return 'top';

      case 'win32': {
        // taskbar occupies some part of the screen excluded from work area
        const primaryDisplay = screen.getPrimaryDisplay();
        const displaySize = primaryDisplay.size;
        const workArea = primaryDisplay.workArea;

        if (workArea.width < displaySize.width) {
          return workArea.x > 0 ? 'left' : 'right';
        } else if (workArea.height < displaySize.height) {
          return workArea.y > 0 ? 'top' : 'bottom';
        } else {
          return 'none';
        }
      }

      default:
        return 'none';
    }
  }
}

export default class WindowController {
  private width: number;
  private height: number;
  private windowPositioning: IWindowPositioning;
  private isWindowReady = false;

  get window(): BrowserWindow {
    return this.windowValue;
  }

  get webContents(): WebContents {
    return this.windowValue.webContents;
  }

  constructor(private windowValue: BrowserWindow, tray: Tray) {
    const [width, height] = windowValue.getSize();
    this.width = width;
    this.height = height;
    this.windowPositioning =
      process.platform === 'linux'
        ? new StandaloneWindowPositioning()
        : new AttachedToTrayWindowPositioning(tray);

    this.installDisplayMetricsHandler();
    this.installWindowReadyHandlers();
  }

  public show(whenReady: boolean = true) {
    if (whenReady) {
      this.executeWhenWindowIsReady(() => this.showImmediately());
    } else {
      this.showImmediately();
    }
  }

  public hide() {
    this.windowValue.hide();
  }

  public toggle() {
    if (this.windowValue.isVisible()) {
      this.hide();
    } else {
      this.show();
    }
  }

  public isVisible(): boolean {
    return this.windowValue.isVisible();
  }

  public send(event: string, ...data: any[]): void {
    this.windowValue.webContents.send(event, ...data);
  }

  private showImmediately() {
    const window = this.windowValue;

    this.updatePosition();
    this.notifyUpdateWindowShape();

    window.show();
    window.focus();
  }

  private updatePosition() {
    const { x, y } = this.windowPositioning.getPosition(this.windowValue);
    this.windowValue.setPosition(x, y, false);
  }

  private notifyUpdateWindowShape() {
    const shapeParameters = this.windowPositioning.getWindowShapeParameters(this.windowValue);
    this.windowValue.webContents.send('update-window-shape', shapeParameters);
  }

  // Installs display event handlers to update the window position on any changes in the display or
  // workarea dimensions.
  private installDisplayMetricsHandler() {
    screen.addListener('display-metrics-changed', this.onDisplayMetricsChanged);
    this.windowValue.once('closed', () => {
      screen.removeListener('display-metrics-changed', this.onDisplayMetricsChanged);
    });
  }

  private onDisplayMetricsChanged = (
    _event: Electron.Event,
    _display: Display,
    changedMetrics: string[],
  ) => {
    if (changedMetrics.includes('workArea') && this.windowValue.isVisible()) {
      this.updatePosition();
      this.notifyUpdateWindowShape();
    }

    // On linux, the window won't be properly rescaled back to it's original
    // size if the DPI scaling factor is changed.
    // https://github.com/electron/electron/issues/11050
    if (process.platform === 'linux' && changedMetrics.includes('scaleFactor')) {
      this.forceResizeWindow();
    }
  };

  private forceResizeWindow() {
    this.windowValue.setSize(this.width, this.height);
  }

  private installWindowReadyHandlers() {
    this.windowValue.once('ready-to-show', () => {
      this.isWindowReady = true;
    });
  }

  private executeWhenWindowIsReady(closure: () => void) {
    if (this.isWindowReady) {
      closure();
    } else {
      this.windowValue.once('ready-to-show', () => {
        closure();
      });
    }
  }
}
