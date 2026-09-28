export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/test-db") {
      try {
        const result = await env.DB
          .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
          .all();

        return Response.json({
          ok: true,
          database: "iglass-production",
          tables: result.results ?? []
        });
      } catch (error) {
        return Response.json({
          ok: false,
          error: "D1 database connection failed",
          details: String(error?.message || error)
        }, { status: 500 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
