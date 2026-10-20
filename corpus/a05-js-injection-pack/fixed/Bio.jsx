import DOMPurify from 'dompurify';
export function Bio(props) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.bio) }} />;
}
