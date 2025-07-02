defmodule ExTwilioWebhook.PlugTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias ExTwilioWebhook.Plug, as: WebhookPlug

  @public_host "https://mycompany.com"

  defmodule Helpers do
    def resolve_public_host do
      "https://mycompany.com"
    end

    def get_path_pattern(pattern) do
      pattern
    end
  end

  @host_mfa {Helpers, :resolve_public_host, []}

  describe "path matching" do
    test "does not process requests when path doesn't match string pattern exactly" do
      opts = WebhookPlug.init(at: "/webhook", public_host: @public_host, secret: "test")
      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn == before_conn
    end

    test "does not process requests when path doesn't match regex pattern" do
      opts = WebhookPlug.init(at: ~r"^/webhook", public_host: @public_host, secret: "test")
      before_conn = conn(:post, "/invalid/path", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn == before_conn
    end

    test "processes requests when path is ignored" do
      opts = WebhookPlug.init(at: :all, public_host: @public_host, secret: "test")
      before_conn = conn(:post, "/webhook/path", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches string pattern exactly" do
      opts = WebhookPlug.init(at: "/webhook/twilio", public_host: @public_host, secret: "test")
      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches regex pattern" do
      opts = WebhookPlug.init(at: ~r"^/webhook", public_host: @public_host, secret: "test")
      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches string pattern exactly from MFA" do
      opts =
        WebhookPlug.init(
          at: {Helpers, :get_path_pattern, ["/webhook/twilio"]},
          public_host: @public_host,
          secret: "test"
        )

      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches regex pattern from MFA" do
      opts =
        WebhookPlug.init(
          at: {Helpers, :get_path_pattern, [~r"^/webhook"]},
          public_host: @public_host,
          secret: "test"
        )

      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches string pattern exactly from callback" do
      opts =
        WebhookPlug.init(
          at: fn -> "/webhook/twilio" end,
          public_host: @public_host,
          secret: "test"
        )

      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches string pattern exactly with MFA host" do
      opts = WebhookPlug.init(at: "/webhook/twilio", public_host: @host_mfa, secret: "test")
      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end

    test "processes requests when path matches regex pattern with MFA host" do
      opts = WebhookPlug.init(at: ~r"^/webhook", public_host: @host_mfa, secret: "test")
      before_conn = conn(:post, "/webhook/twilio", "test body")
      after_conn = WebhookPlug.call(before_conn, opts)
      assert after_conn.halted
      assert after_conn.status >= 400
    end
  end

  def alt_cache_raw_body(conn, opts) do
    with {:ok, body, conn} <- Plug.Conn.read_body(conn, opts) do
      conn = update_in(conn.assigns[:raw_body], &[body | &1 || []])

      {:ok, body, conn}
    end
  end

  @parser_opts [
    parsers: [:json, :urlencoded],
    json_decoder: Jason,
    body_reader: {ExTwilioWebhook.BodyReader, :read_body, []}
  ]
  @init Plug.Parsers.init(@parser_opts)
  @init_with_different_cache @parser_opts
                             |> Keyword.put(:body_reader, {__MODULE__, :alt_cache_raw_body, []})
                             |> Plug.Parsers.init()

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

    test "lets request through and handles raw body passed in a closure" do
      opts =
        WebhookPlug.init(
          at: "/twilio/conference_status",
          public_host: "https://0447-85-232-252-1.eu.ngrok.io",
          secret: "c73504dac708a5cd9f57e80c747bb488",
          raw_body: fn conn -> conn.assigns.raw_body end
        )

      conn =
        conn(:post, @path, @body)
        |> Plug.Conn.put_req_header("x-twilio-signature", "cN6s/ajWzahiBNHjFpssnkbSQSM=")
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Parsers.call(@init_with_different_cache)
        |> WebhookPlug.call(opts)

      refute conn.halted
    end

    test "lets request through when signature matches and with a list of auth tokens" do
      tokens = [
        "bf0a3ff1ce8cdece9a76432e52659ff6",
        "c73504dac708a5cd9f57e80c747bb488"
      ]

      opts =
        WebhookPlug.init(
          at: "/twilio/conference_status",
          public_host: "https://0447-85-232-252-1.eu.ngrok.io",
          secret: tokens
        )

      conn =
        conn(:post, @path, @body)
        |> Plug.Conn.put_req_header("x-twilio-signature", "cN6s/ajWzahiBNHjFpssnkbSQSM=")
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Parsers.call(@init)
        |> WebhookPlug.call(opts)

      refute conn.halted
    end

    test "lets request through when signature matches and with a function returning list of tokens" do
      tokens = [
        "bf0a3ff1ce8cdece9a76432e52659ff6",
        "c73504dac708a5cd9f57e80c747bb488"
      ]

      secret_fun = fn _ -> tokens end

      opts =
        WebhookPlug.init(
          at: "/twilio/conference_status",
          public_host: "https://0447-85-232-252-1.eu.ngrok.io",
          secret: secret_fun
        )

      conn =
        conn(:post, @path, @body)
        |> Plug.Conn.put_req_header("x-twilio-signature", "cN6s/ajWzahiBNHjFpssnkbSQSM=")
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Plug.Parsers.call(@init)
        |> WebhookPlug.call(opts)

      refute conn.halted
    end

    test "halts the request when signature is invalid with a single auth token" do
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

    test "halts the request when signature is invalid with a list of auth tokens" do
      tokens = [
        "bf0a3ff1ce8cdece9a76432e52659ff6",
        "c73504dac708a5cd9f57e80c747bb488"
      ]

      opts =
        WebhookPlug.init(
          at: "/twilio/conference_status",
          public_host: "https://0447-85-232-252-1.eu.ngrok.io",
          secret: tokens
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

  describe "normalize_request_url/2" do
    test "normalizes url to host+path+query" do
      path = "/twilio/conference_status.xml?waiter_id=38"

      conn = conn(:post, path, "")

      actual = WebhookPlug.normalize_request_url(@public_host, conn)
      assert actual == "#{@public_host}#{path}"
    end
  end
end
