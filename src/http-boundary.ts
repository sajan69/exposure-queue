/** Restrict the local service to its exact numeric loopback authority. */
export function acceptsLocalRequest(
  authority: string,
  host: string | undefined,
  origin: string | undefined,
  fetchSite: string | undefined,
): boolean {
  if (!/^127\.0\.0\.1:[0-9]{1,5}$/.test(authority)) return false;
  const port = Number(authority.split(':')[1]);
  if (port < 1 || port > 65535 || host !== authority) return false;
  if (origin !== undefined && origin !== `http://${authority}`) return false;
  return (
    fetchSite === undefined ||
    fetchSite === 'same-origin' ||
    fetchSite === 'none'
  );
}
