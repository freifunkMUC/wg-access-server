import { PropsWithChildren } from 'react';

interface Props {
  for: string;
  value: string;
}

export function TabPanel(props: PropsWithChildren<Props>) {
  return (
    <div style={{ padding: '1.5rem 1rem' }} hidden={props.for !== props.value}>
      {props.children}
    </div>
  );
}
