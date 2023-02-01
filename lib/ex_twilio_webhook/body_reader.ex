defmodule ExTwilioWebhook.BodyReader do
  @moduledoc """
  Body reader module that allows you to parse the request while
  keeping its body at the same time.

  Usage:

  ```
  plug Plug.Parsers,
    parsers: [:urlencoded, :json],
    pass: ["*/*"],
    body_reader: {ExTwilioWebhook.BodyReader, :read_body, []},
    json_decoder: Jason
  ```

  The original raw body can be found at `conn.private[:raw_body]`.
  """

  def read_body(conn, opts) do
    {:ok, body, conn} = Plug.Conn.read_body(conn, opts)

    conn =
      update_in(conn.private, fn private ->
        Map.put(private || %{}, :raw_body, body)
      end)

    {:ok, body, conn}
  end
end
