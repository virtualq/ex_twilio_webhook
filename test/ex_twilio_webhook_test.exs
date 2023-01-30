defmodule ExTwilioWebhookTest do
  use ExUnit.Case
  doctest ExTwilioWebhook

  test "greets the world" do
    assert ExTwilioWebhook.hello() == :world
  end
end
