defmodule ExTwilioWebhook.HashHelpers do
  def hmac_sha1_base64(key, data) when is_binary(key) and is_binary(data) do
    digested = :crypto.mac(:hmac, :sha, key, data)
    Base.encode64(digested)
  end
end
