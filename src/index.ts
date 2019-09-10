import {respond} from './handler';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request: Request) {
  var resp: Response;
  try {
    resp = await respond(request);
  } catch (e) {
    resp = new Response(`Error: ${e}`, {status: 500});
  }
  return resp;
}
