export async function onRequest(context) {
  const url = new URL(context.request.url);

  return new Response(
    JSON.stringify(
      {
        ok: true,
        path: url.pathname,
        method: context.request.method,
      },
      null,
      2,
    ),
    {
      headers: {
        "content-type": "application/json; charset=utf-8",
      },
    },
  );
}
