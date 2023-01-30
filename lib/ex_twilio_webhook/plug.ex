defmodule ExTwilioWebhook.Plug do
  @moduledoc """
  A module plug that verifies Twilio webhook signatures and halts
  the request if the signature is invalid.

  Due to the fact that the signature must be calculated based on the
  request's raw body, this plug must be placed in your plug pipeline
  before 
  """
  alias ExTwilioWebhook.HashHelpers

  @behaviour Plug

  import Plug.Conn

  defmodule Settings do
    @type t :: %__MODULE__{
            secret: String.t() | mfa() | function(),
            path_info: [String.t()],
            public_host: String.t() | mfa()
          }

    defstruct [:secret, :path_info, :public_host]
  end

  @impl true
  def init(opts \\ []) do
    at = Keyword.fetch!(opts, :at)
    path_info = String.split(at, "/", trim: true)
    secret = Keyword.fetch!(opts, :secret)
    public_host = Keyword.fetch!(opts, :public_host)

    %Settings{
      path_info: path_info,
      secret: secret,
      public_host: parse_setting!(public_host)
    }
  end

  @impl true
  def call(%Plug.Conn{path_info: path_info} = conn, %Settings{
        path_info: path_info,
        secret: secret,
        public_host: public_host
      })
      when not is_nil(secret) do
    secret = parse_setting!(secret)
    url = normalize_url(public_host, conn)

    with [signature] <- get_req_header(conn, "x-twilio-signature"),
         {:ok, payload, _} <- read_body(conn),
         true <-
           HashHelpers.validate_request_with_body(secret, signature, url, payload) do
      conn
    else
      _ ->
        deny_access(conn)
    end
  end

  def call(%Plug.Conn{path_info: path_info} = conn, %Settings{path_info: path_info}) do
    deny_access(conn)
  end

  def call(conn, _), do: conn

  defp parse_setting!({m, f, a}), do: apply(m, f, a)
  defp parse_setting!(fun) when is_function(fun, 0), do: fun.()
  defp parse_setting!(string) when is_binary(string), do: string

  defp normalize_url(public_host, %Plug.Conn{} = conn) do
    normalized_query =
      case conn.query_string do
        blank when blank in ["", nil] -> ""
        query -> "?#{query}"
      end

    public_host <> conn.request_path <> normalized_query
  end

  defp deny_access(conn) do
    conn
    |> send_resp(400, "Bad request.")
    |> halt()
  end
end
