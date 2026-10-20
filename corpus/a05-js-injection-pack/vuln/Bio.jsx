export function Bio(props) {
  return <div dangerouslySetInnerHTML={{ __html: props.bio }} />;
}
