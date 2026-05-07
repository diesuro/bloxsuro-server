import os
import requests
import discord
from discord import app_commands
from discord.ext import commands

API_BASE_URL = os.environ.get("API_BASE_URL", "https://bloxsuro-server.onrender.com").rstrip("/")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

ALLOWED_USERS = {
    964974537156472884,
    398692582063996929,
}


def allowed(interaction: discord.Interaction) -> bool:
    return interaction.user.id in ALLOWED_USERS


async def no_access(interaction: discord.Interaction):
    await interaction.response.send_message(
        "━━━━━━━━━━━━━━━━━━━━\n"
        "BLOXSURO ACCESS\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "You are not authorized to use this command.\n"
        "━━━━━━━━━━━━━━━━━━━━",
        ephemeral=True,
    )


def api_post(path: str, payload: dict):
    if not ADMIN_SECRET:
        return {"ok": False, "error": "ADMIN_SECRET is not configured."}

    data = dict(payload or {})
    data["secret"] = ADMIN_SECRET

    try:
        response = requests.post(f"{API_BASE_URL}{path}", json=data, timeout=18)
        try:
            body = response.json()
        except Exception:
            return {"ok": False, "error": f"Invalid API response. HTTP {response.status_code}"}

        if response.status_code >= 400 and not body.get("error"):
            body["error"] = f"HTTP {response.status_code}"

        return body
    except requests.RequestException as exc:
        return {"ok": False, "error": f"API unavailable: {exc}"}


def block(title: str, lines: list[str]) -> str:
    return (
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"{title}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        + "\n".join(lines)
        + "\n━━━━━━━━━━━━━━━━━━━━"
    )


def format_key_info(data: dict) -> str:
    return block(
        "BLOXSURO LICENSE",
        [
            "KEY",
            f"`{data.get('key', 'N/A')}`",
            "",
            "COPY KEY",
            f"`{data.get('key', 'N/A')}`",
            "",
            "OWNER",
            data.get("owner") or "Not linked",
            "",
            "STATUS",
            data.get("status", "Unknown"),
            "",
            "REMAINING",
            data.get("remaining", "Unknown"),
            "",
            "HWID",
            data.get("hwid") or "Not bound",
        ],
    )


intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    synced = await bot.tree.sync()
    print(f"BLOXSURO bot online as {bot.user}. Synced {len(synced)} commands.")


@bot.tree.command(name="keygen", description="Generate a BLOXSURO license key.")
@app_commands.describe(duration="Duration: 1m, 1h, 1d, 7d, 30d", user="Optional user/name to link to this key")
async def keygen(interaction: discord.Interaction, duration: str = "30d", user: str = ""):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/create", {"duration": duration, "owner": user})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block(
            "BLOXSURO KEY GENERATED",
            [
                "KEY",
                f"`{data.get('key')}`",
                "",
                "COPY KEY",
                f"`{data.get('key')}`",
                "",
                "DURATION",
                data.get("duration", duration),
                "",
                "OWNER",
                data.get("owner") or "Not linked",
                "",
                "EXPIRES",
                data.get("expires", "Unknown"),
            ],
        ),
        ephemeral=True,
    )


@bot.tree.command(name="link", description="Link an existing key to a user/name.")
@app_commands.describe(key="License key", user="User/name to link")
async def link(interaction: discord.Interaction, key: str, user: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/link-owner", {"key": key, "owner": user})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block("BLOXSURO KEY LINKED", ["KEY", f"`{key}`", "", "OWNER", user]),
        ephemeral=True,
    )


@bot.tree.command(name="search", description="Search keys linked to a user/name.")
@app_commands.describe(user="User/name to search, example: bloxkey281381283")
async def search(interaction: discord.Interaction, user: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/search-owner", {"owner": user})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    keys = data.get("keys", [])
    if not keys:
        await interaction.followup.send(
            block("BLOXSURO SEARCH", ["USER", user, "", "RESULT", "No keys found."]),
            ephemeral=True,
        )
        return

    lines = ["USER", user, "", "RESULTS"]
    for item in keys[:10]:
        lines += [
            "",
            "KEY",
            f"`{item.get('key')}`",
            "STATUS",
            item.get("status", "Unknown"),
            "REMAINING",
            item.get("remaining", "Unknown"),
            "HWID",
            item.get("hwid") or "Not bound",
        ]

    await interaction.followup.send(block("BLOXSURO SEARCH", lines), ephemeral=True)


@bot.tree.command(name="keyinfo", description="Show key status, remaining time, owner and HWID.")
@app_commands.describe(key="License key")
async def keyinfo(interaction: discord.Interaction, key: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/key-info", {"key": key})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(format_key_info(data), ephemeral=True)


@bot.tree.command(name="timeleft", description="Check remaining time for a key.")
@app_commands.describe(key="License key")
async def timeleft(interaction: discord.Interaction, key: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/key-info", {"key": key})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block(
            "BLOXSURO TIME LEFT",
            [
                "KEY",
                f"`{data.get('key')}`",
                "",
                "REMAINING",
                data.get("remaining", "Unknown"),
                "",
                "STATUS",
                data.get("status", "Unknown"),
                "",
                "OWNER",
                data.get("owner") or "Not linked",
            ],
        ),
        ephemeral=True,
    )


@bot.tree.command(name="reset_hwid", description="Reset HWID from a key.")
@app_commands.describe(key="License key")
async def reset_hwid(interaction: discord.Interaction, key: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/action", {"action": "reset_hwid", "keys": [key]})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block("BLOXSURO HWID RESET", ["KEY", f"`{key}`", "", "RESULT", "HWID reset completed."]),
        ephemeral=True,
    )


@bot.tree.command(name="disable", description="Disable a key.")
@app_commands.describe(key="License key")
async def disable(interaction: discord.Interaction, key: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/action", {"action": "disable", "keys": [key]})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block("BLOXSURO KEY DISABLED", ["KEY", f"`{key}`", "", "RESULT", "Key disabled."]),
        ephemeral=True,
    )


@bot.tree.command(name="enable", description="Re-enable a disabled key.")
@app_commands.describe(key="License key")
async def enable(interaction: discord.Interaction, key: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/action", {"action": "enable", "keys": [key]})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block("BLOXSURO KEY ENABLED", ["KEY", f"`{key}`", "", "RESULT", "Key enabled."]),
        ephemeral=True,
    )


@bot.tree.command(name="delete", description="Delete a key permanently.")
@app_commands.describe(key="License key")
async def delete(interaction: discord.Interaction, key: str):
    if not allowed(interaction):
        await no_access(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    data = api_post("/admin/action", {"action": "delete", "keys": [key]})
    if not data.get("ok"):
        await interaction.followup.send(block("BLOXSURO ERROR", [data.get("error", "Unknown error")]), ephemeral=True)
        return

    await interaction.followup.send(
        block("BLOXSURO KEY DELETED", ["KEY", f"`{key}`", "", "RESULT", "Key permanently deleted."]),
        ephemeral=True,
    )


if not DISCORD_BOT_TOKEN:
    raise RuntimeError("DISCORD_BOT_TOKEN is not configured.")

bot.run(DISCORD_BOT_TOKEN)
