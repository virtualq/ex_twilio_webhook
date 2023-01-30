defmodule ExTwilioWebhook.PlugTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias ExTwilioWebhook.Plug, as: WebhookPlug

  @public_host "https://mycompany.com"

  test "does not process requests when path doesn't match" do
    opts = WebhookPlug.init(at: "/webhook/twilio", public_host: @public_host, secret: "test")
    before_conn = conn(:get, "/webhook", "test body")
    after_conn = WebhookPlug.call(before_conn, opts)
    assert after_conn == before_conn
  end

  @valid_body_signature "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
  @json_body ~s[{"property": "value", "boolean": true}]
  @url "https://mycompany.com/myapp.php?foo=1&bar=2"
  @path URI.parse(@url).path <> "&bodySHA256=#{@valid_body_signature}"

  test "lets request through when signature matches" do
    opts = WebhookPlug.init(at: "/myapp.php", public_host: @public_host, secret: "12345")

    conn =
      conn(:get, @path, @json_body)
      |> Plug.Conn.put_req_header("x-twilio-signature", "a9nBmqA0ju/hNViExpshrM61xv4=")
      |> Plug.Conn.put_req_header("content-type", "application/json")

    conn = WebhookPlug.call(conn, opts)

    refute conn.halted
  end
end
