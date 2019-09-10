import {isValidJwt} from './jwt';

// Return response
export async function respond(request: Request) {
  // If no path, redirect back to last URL
  const url = new URL(request.url);
  if (url.pathname === '/') {
    return new Response(
      `<html>
      <script type="text/javascript">
        window.history.back();
      </script>
      </html>`,
      {
        status: 200,
        headers: {
          'content-type': 'text/html',
        },
      },
    );
  }

  let isValid = await isValidJwt(request);
  if (!isValid) {
    return new Response('Invalid JWT', {status: 403});
  }

  return new Response('Valid JWT, good job!', {status: 200});
}
