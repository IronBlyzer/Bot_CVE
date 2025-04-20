import discord
from discord import app_commands
from discord.ext import commands, tasks
import requests
import re
import json
import os
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
import asyncio
from collections import defaultdict

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
NVD_API_KEY = os.getenv("NVD_API_KEY")

CACHE_FILE = "cve_cache.json"
CATEGORIES_FILE = "categories.json"
DAILY_SUMMARY_CHANNEL = "cve-resume-quotidien"
PING_ROLE_NAME = "alert-cve"
DEFAULT_CATEGORY = "autres_cve"

BLACKLIST_WORDS = ["The", "This", "There", "That", "From", "With", "Using", "Use", "Without", "When", "After", "CVE", "cve"]

with open(CATEGORIES_FILE, "r") as f:
    CATEGORIES = json.load(f)

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return []

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(list(set(cache)), f)

def save_categories():
    with open(CATEGORIES_FILE, "w") as f:
        json.dump(CATEGORIES, f)

intents = discord.Intents.default()
intents.guilds = True
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree
summary_buffer = []
last_check_time = None

@bot.event
async def on_ready():
    print(f"✅ Bot connecté : {bot.user.name}")
    await tree.sync()
    daily_summary.start()

@tree.command(name="ajout_categorie", description="Ajoute une nouvelle catégorie à surveiller")
@app_commands.checks.has_permissions(administrator=True)
async def ajout_categorie(interaction: discord.Interaction, mot: str):
    mot = mot.strip()
    if mot not in CATEGORIES:
        CATEGORIES.append(mot)
        save_categories()
        await interaction.response.send_message(f"✅ {mot} ajouté à la liste des catégories.")
    else:
        await interaction.response.send_message(f"ℹ️ {mot} est déjà présent.")

@tree.command(name="force_all", description="Analyse toutes les CVE des X derniers jours")
@app_commands.checks.has_permissions(administrator=True)
async def force_all(interaction: discord.Interaction, jours: int = 1000):
    guild = interaction.guild
    await interaction.response.send_message(f"🔁 Analyse forcée des CVE sur {jours} jours...", ephemeral=True)
    await check_cve(guild, ignore_cache=True, days=jours)
    await interaction.followup.send("✅ Analyse complète terminée.", ephemeral=True)

@tree.command(name="force", description="Analyse les CVE récentes (3 jours)")
async def force(interaction: discord.Interaction):
    guild = interaction.guild
    await interaction.response.send_message("🔄 Analyse forcée des CVE...", ephemeral=True)
    await check_cve(guild, days=3)
    await interaction.followup.send("✅ Terminé.", ephemeral=True)

@tree.command(name="status", description="Affiche la date de la dernière vérification")
async def status(interaction: discord.Interaction):
    if last_check_time:
        await interaction.response.send_message(f"🕒 Dernière vérification CVE : {last_check_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    else:
        await interaction.response.send_message("❌ Aucune vérification effectuée pour l'instant.")

@tree.command(name="aide", description="Affiche la liste des commandes")
async def aide(interaction: discord.Interaction):
    commands_list = """
📖 **Commandes disponibles :**

`/force` → Analyse les CVE récentes (3 derniers jours)
`/force_all <jours>` → Analyse toutes les CVE des X derniers jours (ignore le cache)
`/ajout_categorie <mot>` → Ajoute une nouvelle catégorie à surveiller
`/status` → Affiche la date de la dernière vérification
`/cve_info <CVE-ID>` → Affiche les détails d'une CVE (si disponible)
`/aide` → Affiche ce message d’aide
"""
    await interaction.response.send_message(commands_list)


@tree.command(name="cve_info", description="Afficher les infos détaillées d'une CVE")
async def cve_info(interaction: discord.Interaction, cve_id: str):
    headers = {
        "User-Agent": "Discord CVE Bot",
        "apiKey": NVD_API_KEY
    }
    url_v1 = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    url_v2 = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url_v1, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        cve = data.get("result", {}).get("CVE_Items", [])[0]
        desc = cve.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "No description")
    except:
        try:
            response = requests.get(url_v2, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            vuln = data.get("vulnerabilities", [])[0].get("cve", {})
            desc = next((d["value"] for d in vuln.get("descriptions", []) if d["lang"] == "fr"),
                        next((d["value"] for d in vuln.get("descriptions", []) if d["lang"] == "en"), "No description"))
        except:
            await interaction.response.send_message(f"❌ Impossible de récupérer les infos pour {cve_id}.")
            return
    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    await interaction.response.send_message(f"🔍 **{cve_id}**\n{desc}\n🔗 {link}")


@tasks.loop(hours=6)
async def daily_summary():
    for guild in bot.guilds:
        await check_cve(guild)
        if not summary_buffer:
            continue
        channel = discord.utils.get(guild.text_channels, name=DAILY_SUMMARY_CHANNEL)
        if not channel:
            channel = await guild.create_text_channel(DAILY_SUMMARY_CHANNEL)
        date_str = datetime.now().strftime("%Y-%m-%d")
        text = f"🗓 **Résumé des CVE du {date_str}**\n\n" + "\n".join(summary_buffer)
        for chunk in [text[i:i+1990] for i in range(0, len(text), 1990)]:
            await channel.send(chunk)
        summary_buffer.clear()

def fetch_latest_cve(days=1):
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    headers = {
        "User-Agent": "Discord CVE Bot",
        "apiKey": NVD_API_KEY
    }
    chunks = []
    current = start_date
    while current < end_date:
        chunk_end = min(current + timedelta(days=30), end_date)
        chunks.append((current, chunk_end))
        current = chunk_end
    all_results = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(fetch_chunk, s, e, headers) for s, e in chunks]
        for future in futures:
            for cve in future.result():
                all_results.append({
                    "id": cve["cve"]["id"],
                    "summary": next((d["value"] for d in cve["cve"]["descriptions"] if d["lang"] == "fr"),
                                     next((d["value"] for d in cve["cve"]["descriptions"] if d["lang"] == "en"), "No description")),
                    "cvss": cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0),
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve['cve']['id']}"
                })
    return all_results

def fetch_chunk(start, end, headers):
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }
    try:
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Erreur sur la période {start} → {end} : {e}")
        return []

async def check_cve(guild, ignore_cache=False, days=1):
    global last_check_time
    cves = fetch_latest_cve(days=days)
    cache = load_cache()
    new_cache = cache.copy()
    match_counter = defaultdict(int)

    ping_role = discord.utils.get(guild.roles, name=PING_ROLE_NAME)
    if not ping_role:
        try:
            ping_role = await guild.create_role(name=PING_ROLE_NAME, mentionable=True)
        except discord.Forbidden:
            ping_role = None
    role_mention = ping_role.mention if ping_role else ""

    for cve in cves:
        cve_id = cve.get("id", "CVE-???")
        if not ignore_cache and cve_id in cache:
            continue
        summary = cve.get("summary", "")
        cvss = cve.get("cvss", 0)
        link = cve.get("link", "")
        criticite = "🟢 Faible"
        if cvss >= 7:
            criticite = "🔴 Critique"
        elif cvss >= 4:
            criticite = "🔶 Moyenne"

        matched = False
        for cat in CATEGORIES:
            if cat.lower() in summary.lower():
                matched = True
                match_counter[cat] += 1
                channel_name = f"{cat.lower()}"
                discord_channel = discord.utils.get(guild.text_channels, name=channel_name)
                if not discord_channel:
                    discord_channel = await guild.create_text_channel(channel_name)
                msg = (f"{role_mention}\n" if cvss >= 7 else "") + f"**{cve_id}** - {criticite} (CVSS {cvss})\n{summary}\n🔗 {link}"
                for chunk in [msg[i:i+1990] for i in range(0, len(msg), 1990)]:
                    await discord_channel.send(chunk)
                break

        if not matched:
            discord_channel = discord.utils.get(guild.text_channels, name=DEFAULT_CATEGORY)
            if not discord_channel:
                discord_channel = await guild.create_text_channel(DEFAULT_CATEGORY)
            msg = (f"{role_mention}\n" if cvss >= 7 else "") + f"**{cve_id}** - {criticite} (CVSS {cvss})\n{summary}\n🔗 {link}"
            for chunk in [msg[i:i+1990] for i in range(0, len(msg), 1990)]:
                await discord_channel.send(chunk)

        summary_buffer.append(f"**{cve_id}** - {criticite} - {link}")
        new_cache.append(cve_id)

    save_cache(new_cache)
    last_check_time = datetime.utcnow()

    print("\n🧠 Récapitulatif des catégories détectées :")
    for cat, count in match_counter.items():
        print(f"• {cat} : {count} CVE")

@bot.event
async def on_guild_join(guild):
    message = f"""
👋 Merci de m’avoir ajouté sur **{guild.name}** !

📌 **Fonctionnalités :**
• Surveillance automatique des CVE récentes
• Ping du rôle `@alert-cve` pour les failles critiques
• Résumé quotidien dans `#{DAILY_SUMMARY_CHANNEL}`
• Les CVE non catégorisées seront postées dans `#{DEFAULT_CATEGORY}`
• Commandes slash : `/force`, `/force_all <jours>`, `/ajout_categorie <mot>`, `/status`, `/aide`, `/cve_info`
"""
    for channel in guild.text_channels:
        if channel.permissions_for(guild.me).send_messages:
            await channel.send(message)
            break

bot.run(TOKEN)
