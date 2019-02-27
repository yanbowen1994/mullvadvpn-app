import * as React from 'react';

const AUTOHIDE_TIMEOUT = 1000;

interface IProps {
  autoHide: boolean;
  trackPadding: { x: number; y: number };
  onScroll?: (value: IScrollEvent) => void;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

interface IState {
  canScroll: boolean;
  showScrollIndicators: boolean;
  showTrack: boolean;
  isTrackHovered: boolean;
  isDragging: boolean;
  dragStart: {
    x: number;
    y: number;
  };
  isWide: boolean;
}

export interface IScrollEvent {
  scrollLeft: number;
  scrollTop: number;
}
export type ScrollPosition = 'top' | 'bottom' | 'middle';

interface IScrollbarUpdateContext {
  size: boolean;
  position: boolean;
}

export default class CustomScrollbars extends React.Component<IProps, IState> {
  public static defaultProps: IProps = {
    // auto-hide on macOS by default
    autoHide: process.platform === 'darwin',
    trackPadding: { x: 2, y: 2 },
  };

  public state = {
    canScroll: false,
    showScrollIndicators: true,
    showTrack: false,
    isTrackHovered: false,
    isDragging: false,
    dragStart: { x: 0, y: 0 },
    isWide: false,
  };

  private scrollableRef = React.createRef<HTMLDivElement>();
  private trackRef = React.createRef<HTMLDivElement>();
  private thumbRef = React.createRef<HTMLDivElement>();
  private autoHideTimer?: NodeJS.Timeout;

  public scrollTo(x: number, y: number) {
    const scrollable = this.scrollableRef.current;
    if (scrollable) {
      scrollable.scrollLeft = x;
      scrollable.scrollTop = y;
    }
  }

  public scrollToElement(child: HTMLElement, scrollPosition: ScrollPosition) {
    const scrollable = this.scrollableRef.current;
    if (scrollable) {
      // throw if child is not a descendant of scroll view
      if (!scrollable.contains(child)) {
        throw new Error(
          'Cannot scroll to an element which is not a descendant of CustomScrollbars.',
        );
      }

      const scrollTop = this.computeScrollTop(scrollable, child, scrollPosition);
      this.scrollTo(0, scrollTop);
    }
  }

  public componentDidMount() {
    this.updateScrollbarsHelper({
      position: true,
      size: true,
    });

    document.addEventListener('mousemove', this.handleMouseMove);
    document.addEventListener('mouseup', this.handleMouseUp);
    document.addEventListener('mousedown', this.handleMouseDown);

    // show scroll indicators briefly when mounted
    if (this.props.autoHide) {
      this.startAutoHide();
    }
  }

  public shouldComponentUpdate(nextProps: IProps, nextState: IState) {
    const prevProps = this.props;
    const prevState = this.state;

    return (
      prevProps.children !== nextProps.children ||
      prevProps.autoHide !== nextProps.autoHide ||
      prevProps.trackPadding.x !== nextProps.trackPadding.x ||
      prevProps.trackPadding.y !== nextProps.trackPadding.y ||
      prevState.canScroll !== nextState.canScroll ||
      prevState.showScrollIndicators !== nextState.showScrollIndicators ||
      prevState.showTrack !== nextState.showTrack ||
      prevState.isTrackHovered !== nextState.isTrackHovered ||
      prevState.isDragging !== nextState.isDragging ||
      prevState.isWide !== nextState.isWide
    );
  }

  public componentWillUnmount() {
    this.stopAutoHide();

    document.removeEventListener('mousemove', this.handleMouseMove);
    document.removeEventListener('mouseup', this.handleMouseUp);
    document.removeEventListener('mousedown', this.handleMouseDown);
  }

  public componentDidUpdate() {
    this.updateScrollbarsHelper({
      position: true,
      size: true,
    });
  }

  public render() {
    const {
      autoHide: _autoHide,
      trackPadding: _trackPadding,
      onScroll: _onScroll,
      children,
      ...otherProps
    } = this.props;
    const showScrollbars = this.state.canScroll && this.state.showScrollIndicators;
    const thumbAnimationClass = showScrollbars ? ' custom-scrollbars__thumb--visible' : '';
    const thumbActiveClass =
      this.state.isTrackHovered || this.state.isDragging ? ' custom-scrollbars__thumb--active' : '';
    const thumbWideClass = this.state.isWide ? ' custom-scrollbars__thumb--wide' : '';
    const trackClass =
      showScrollbars && this.state.showTrack ? ' custom-scrollbars__track--visible' : '';

    return (
      <div {...otherProps} className="custom-scrollbars">
        <div className={`custom-scrollbars__track ${trackClass}`} ref={this.trackRef} />
        <div
          className={`custom-scrollbars__thumb ${thumbWideClass} ${thumbActiveClass} ${thumbAnimationClass}`}
          style={{ position: 'absolute', top: 0, right: 0 }}
          ref={this.thumbRef}
        />
        <div
          className="custom-scrollbars__scrollable"
          style={{ overflow: 'auto' }}
          onScroll={this.onScroll}
          ref={this.scrollableRef}>
          {children}
        </div>
      </div>
    );
  }

  private onScroll = () => {
    this.updateScrollbarsHelper({ position: true });

    if (this.props.autoHide) {
      this.ensureScrollbarsVisible();

      // only auto-hide when scrolling with mousewheel
      if (!this.state.isDragging) {
        this.startAutoHide();
      }
    } else {
      // only auto-shrink when scrolling with mousewheel
      if (!this.state.isDragging) {
        this.startAutoShrink();
      }
    }

    const scrollView = this.scrollableRef.current;
    if (scrollView && this.props.onScroll) {
      this.props.onScroll({
        scrollLeft: scrollView.scrollLeft,
        scrollTop: scrollView.scrollTop,
      });
    }
  };

  private handleEnterTrack = () => {
    this.stopAutoHide();
    this.setState({
      isTrackHovered: true,
      showScrollIndicators: true,
      showTrack: true,
      isWide: true,
    });
  };

  private handleLeaveTrack = () => {
    this.setState({
      isTrackHovered: false,
    });

    // do not hide the scrollbar if user is dragging a thumb but left the track area.
    if (!this.state.isDragging) {
      if (this.props.autoHide) {
        this.startAutoHide();
      } else {
        this.startAutoShrink();
      }
    }
  };

  private handleMouseDown = (event: MouseEvent) => {
    const thumb = this.thumbRef.current;
    const cursorPosition = {
      x: event.clientX,
      y: event.clientY,
    };

    // initiate dragging when user clicked inside of thumb
    if (thumb && this.isPointInsideOfElement(thumb, cursorPosition)) {
      this.setState({
        isDragging: true,
        dragStart: this.getPointRelativeToElement(thumb, cursorPosition),
      });
    }
  };

  private handleMouseUp = (event: MouseEvent) => {
    if (!this.state.isDragging) {
      return;
    }

    this.setState({
      isDragging: false,
    });

    const track = this.trackRef.current;
    if (track) {
      // Make sure to auto-hide the scrollbar if cursor ended up outside of scroll track
      const cursorPosition = {
        x: event.clientX,
        y: event.clientY,
      };

      if (!this.isPointInsideOfElement(track, cursorPosition)) {
        if (this.props.autoHide) {
          this.startAutoHide();
        } else {
          this.startAutoShrink();
        }
      }
    }
  };

  private handleMouseMove = (event: MouseEvent) => {
    const scrollable = this.scrollableRef.current;
    const thumb = this.thumbRef.current;
    const track = this.trackRef.current;

    const cursorPosition = {
      x: event.clientX,
      y: event.clientY,
    };

    if (this.state.isDragging && scrollable && thumb) {
      // the content height of the scroll view
      const scrollHeight = scrollable.scrollHeight;

      // the visible height of the scroll view
      const visibleHeight = scrollable.offsetHeight;

      // lowest point of scrollTop
      const maxScrollTop = scrollHeight - visibleHeight;

      // Map absolute cursor coordinate to point in scroll container
      const pointInScrollContainer = this.getPointRelativeToElement(scrollable, cursorPosition);

      // calculate the thumb boundary to make sure that the visual appearance of
      // a thumb at the lowest point matches the bottom of scrollable view
      const thumbBoundary = this.computeTrackLength(scrollable) - thumb.clientHeight;
      const thumbTop =
        pointInScrollContainer.y - this.state.dragStart.y - this.props.trackPadding.y;
      const newScrollTop = (thumbTop / thumbBoundary) * maxScrollTop;

      scrollable.scrollTop = newScrollTop;
    }

    if (scrollable && track) {
      const intersectsTrack = this.isPointInsideOfElement(track, cursorPosition);

      if (!this.state.isTrackHovered && intersectsTrack) {
        this.handleEnterTrack();
      } else if (this.state.isTrackHovered && !intersectsTrack) {
        this.handleLeaveTrack();
      }
    }
  };

  private ensureScrollbarsVisible() {
    if (!this.state.showScrollIndicators) {
      this.setState({
        showScrollIndicators: true,
      });
    }
  }

  private startAutoHide() {
    if (this.autoHideTimer) {
      clearTimeout(this.autoHideTimer);
    }
    this.autoHideTimer = setTimeout(() => {
      this.setState({
        showScrollIndicators: false,
        showTrack: false,
        isWide: false,
      });
    }, AUTOHIDE_TIMEOUT);
  }

  private startAutoShrink() {
    if (this.autoHideTimer) {
      clearTimeout(this.autoHideTimer);
    }

    this.autoHideTimer = setTimeout(() => {
      this.setState({
        showTrack: false,
        isWide: false,
      });
    }, AUTOHIDE_TIMEOUT);
  }

  private stopAutoHide() {
    if (this.autoHideTimer) {
      clearTimeout(this.autoHideTimer);
      this.autoHideTimer = undefined;
    }
  }

  private isPointInsideOfElement(element: HTMLElement, point: { x: number; y: number }) {
    const rect = element.getBoundingClientRect();
    return (
      point.x >= rect.left && point.x <= rect.right && point.y >= rect.top && point.y <= rect.bottom
    );
  }

  private getPointRelativeToElement(element: HTMLElement, point: { x: number; y: number }) {
    const rect = element.getBoundingClientRect();
    return {
      x: point.x - rect.left,
      y: point.y - rect.top,
    };
  }

  private computeTrackLength(scrollable: HTMLElement) {
    return scrollable.offsetHeight - this.props.trackPadding.y * 2;
  }

  // Computes the position of child element within scrollable container
  private computeOffsetTop(scrollable: HTMLElement, child: HTMLElement) {
    let offsetTop = 0;
    let node = child;

    while (scrollable.contains(node)) {
      offsetTop += node.offsetTop;
      if (node.offsetParent) {
        node = node.offsetParent as HTMLElement;
      } else {
        break;
      }
    }

    return offsetTop;
  }

  private computeScrollTop(
    scrollable: HTMLElement,
    child: HTMLElement,
    scrollPosition: ScrollPosition,
  ) {
    const offsetTop = this.computeOffsetTop(scrollable, child);

    switch (scrollPosition) {
      case 'top':
        return offsetTop;

      case 'bottom':
        return offsetTop - (scrollable.offsetHeight - child.clientHeight);

      case 'middle':
        return offsetTop - (scrollable.offsetHeight - child.clientHeight) * 0.5;
    }
  }

  private computeThumbPosition(scrollable: HTMLElement, thumb: HTMLElement) {
    // the content height of the scroll view
    const scrollHeight = scrollable.scrollHeight;

    // the visible height of the scroll view
    const visibleHeight = scrollable.offsetHeight;

    // scroll offset
    const scrollTop = scrollable.scrollTop;

    // lowest point of scrollTop
    const maxScrollTop = scrollHeight - visibleHeight;

    // calculate scroll position within 0..1 range
    const scrollPosition = scrollHeight > 0 ? scrollTop / maxScrollTop : 0;

    // calculate the thumb boundary to make sure that the visual appearance of
    // a thumb at the lowest point matches the bottom of scrollable view
    const thumbBoundary = this.computeTrackLength(scrollable) - thumb.clientHeight;

    // calculate thumb position based on scroll progress and thumb boundary
    // adding vertical inset to adjust the thumb's appearance
    const thumbPosition = thumbBoundary * scrollPosition + this.props.trackPadding.y;

    return {
      x: -this.props.trackPadding.x,
      y: thumbPosition,
    };
  }

  private computeThumbHeight(scrollable: HTMLElement) {
    const scrollHeight = scrollable.scrollHeight;
    const visibleHeight = scrollable.offsetHeight;

    const thumbHeight = (visibleHeight / scrollHeight) * visibleHeight;

    // ensure that the scroll thumb doesn't shrink to nano size
    return Math.max(thumbHeight, 8);
  }

  private updateScrollbarsHelper(updateFlags: Partial<IScrollbarUpdateContext>) {
    const scrollable = this.scrollableRef.current;
    const thumb = this.thumbRef.current;
    if (scrollable && thumb) {
      this.updateScrollbars(scrollable, thumb, updateFlags);
    }
  }

  private updateScrollbars(
    scrollable: HTMLElement,
    thumb: HTMLElement,
    context: Partial<IScrollbarUpdateContext>,
  ) {
    if (context.size) {
      const thumbHeight = this.computeThumbHeight(scrollable);
      thumb.style.setProperty('height', thumbHeight + 'px');

      // hide thumb when there is nothing to scroll
      const canScroll = thumbHeight < scrollable.offsetHeight;
      if (this.state.canScroll !== canScroll) {
        this.setState({ canScroll });

        // flash the scroll indicators when the view becomes scrollable
        if (this.props.autoHide && canScroll) {
          this.startAutoHide();
          this.ensureScrollbarsVisible();
        }
      }
    }

    if (context.position) {
      const { x, y } = this.computeThumbPosition(scrollable, thumb);
      thumb.style.setProperty('transform', `translate(${x}px, ${y}px)`);
    }
  }
}
