import React, { Component, PropsWithChildren } from 'react';

interface Props {
  for: string;
  value: string;
}

export class TabPanel extends Component<PropsWithChildren<Props>> {
  render() {
    return (
      <div style={{ padding: '1.5rem 1rem' }} hidden={this.props.for !== this.props.value}>
        {this.props.children}
      </div>
    );
  }
}
