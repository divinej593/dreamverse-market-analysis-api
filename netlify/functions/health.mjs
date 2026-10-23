
export default async () => {
  return new Response(
    JSON.stringify({
      ok: true,
      service: "dreamverse-market-analysis-api",
      message: "Backend is running."
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
};
