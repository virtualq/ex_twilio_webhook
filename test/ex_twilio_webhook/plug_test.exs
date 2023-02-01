defmodule ExTwilioWebhook.PlugTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias ExTwilioWebhook.Plug, as: WebhookPlug

  @public_host "https://mycompany.com"

  test "does not process requests when path doesn't match" do
    opts = WebhookPlug.init(at: "/webhook/twilio", public_host: @public_host, secret: "test")
    before_conn = conn(:post, "/webhook", "test body")
    after_conn = WebhookPlug.call(before_conn, opts)
    assert after_conn == before_conn
  end

  @parser_opts [
    parsers: [:json, :urlencoded],
    json_decoder: Jason,
    body_reader: {ExTwilioWebhook.BodyReader, :read_body, []}
  ]
  @init Plug.Parsers.init(@parser_opts)

  describe "with urlencoded payload" do
    @body "AccountSid=ACe497b94cea336b5d573d9667ffda50bf&AddOns=%7B+%22status%22%3A+%22successful%22%2C+%22message%22%3A+null%2C+%22code%22%3A+null%2C+%22results%22%3A+%7B+%7D+%7D&ApiVersion=2010-04-01&From=%2B15017122661&FromCity=SAN+FRANCISCO&FromCountry=US&FromState=CA&FromZip=94903&To=%2B15558675310&ToCity=SAN+FRANCISCO&ToCountry=US&ToState=CA&ToZip=94105&Body=Ahoy&MessageSid=SMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&NumMedia=0&NumSegments=1&ReferralNumMedia=0&SmsMessageSid=SMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&SmsSid=SMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&SmsStatus=received"
    @path "/twilio/conference_status?waiter_id=42"

    test "lets request through when signature matches" do
      opts =
        WebhookPlug.init(
          at: "/twilio/conference_status",
          public_host: "https://0447-85-232-252-1.eu.ngrok.io",
          secret: "c73504dac708a5cd9f57e80c747bb488"
        )

      conn =
        conn(:post, @path, @body)
        |> Plug.Conn.put_req_header("x-twilio-signature", "cN6s/ajWzahiBNHjFpssnkbSQSM=")
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Parsers.call(@init)
        |> WebhookPlug.call(opts)

      refute conn.halted
    end

    test "halts the request when signature is invalid" do
      opts =
        WebhookPlug.init(
          at: "/twilio/conference_status",
          public_host: "https://0447-85-232-252-1.eu.ngrok.io",
          secret: "c73504dac708a5cd9f57e80c747bb488"
        )

      conn =
        conn(:post, @path, @body)
        |> Plug.Conn.put_req_header("x-twilio-signature", "cN6s/bbbzahiBNHjFpssnkbSQSM=")
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Parsers.call(@init)
        |> WebhookPlug.call(opts)

      assert conn.halted
    end
  end
end
