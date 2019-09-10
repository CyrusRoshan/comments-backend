import {getEmailFromJWT, isValidJWT} from './jwt';

// Return response
export async function respond(request: Request) {
  // If no path, redirect back to last URL
  const url = new URL(request.url);
  if (url.pathname === '/return') {
    return scriptResponse('window.history.back();');
  }

  const isValid = await isValidJWT(request);
  if (!isValid) {
    return new Response('Invalid JWT', {status: 403});
  }

  const email = await getEmailFromJWT(request);
  // do stuff with request body JSON
  // kv stuff here
  // return response

  return new Response(`Valid JWT, ${email}, good job!`, {status: 200});
}

function scriptResponse(script: string) {
  return new Response(
    `<html>
      <script type="text/javascript">
        ${script}
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
