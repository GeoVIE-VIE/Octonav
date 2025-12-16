# Discord YouTube Music Bot

A Discord bot that plays YouTube audio in voice channels. Just paste a YouTube link and it plays automatically!

## Features

- **Auto-Play**: Automatically detects and plays YouTube links posted in chat
- **Queue System**: Queue multiple songs, view queue, loop, and more
- **Playlist Support**: Add entire YouTube playlists to the queue
- **Search**: Search YouTube directly with `!play <search terms>`
- **Interactive Controls**: Button controls for pause, skip, stop, and queue
- **Rich Embeds**: Beautiful now-playing embeds with thumbnails

## Requirements

- **Node.js** v18 or higher
- **FFmpeg** (for audio processing)

## Installation

### 1. Install FFmpeg

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install ffmpeg
```

**CentOS/RHEL:**
```bash
sudo yum install ffmpeg
```

**macOS:**
```bash
brew install ffmpeg
```

**Windows:**
Download from https://ffmpeg.org/download.html and add to PATH

### 2. Clone and Setup

```bash
cd discord-youtube-bot

# Install dependencies
npm install
```

### 3. Configure the Bot

```bash
# Copy the example config
cp config.example.json config.json

# Edit config.json and add your bot token
```

Edit `config.json`:
```json
{
  "token": "YOUR_DISCORD_BOT_TOKEN_HERE",
  "prefix": "!",
  "autoPlay": true
}
```

### 4. Create a Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and give it a name
3. Go to the "Bot" section and click "Add Bot"
4. Click "Reset Token" to get your bot token (copy it to config.json)
5. **Enable these Privileged Intents:**
   - MESSAGE CONTENT INTENT (required!)
   - SERVER MEMBERS INTENT
   - PRESENCE INTENT
6. Go to OAuth2 > URL Generator
7. Select scopes: `bot`, `applications.commands`
8. Select permissions:
   - Send Messages
   - Embed Links
   - Connect
   - Speak
   - Use Voice Activity
9. Copy the generated URL and open it to invite the bot to your server

### 5. Run the Bot

```bash
# Start the bot
npm start

# Or for development (auto-restart on changes)
npm run dev
```

## Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `!play <url/search>` | `!p` | Play a YouTube video or search |
| `!pause` | - | Pause the current song |
| `!resume` | `!r` | Resume playback |
| `!skip` | `!s` | Skip to the next song |
| `!stop` | - | Stop playback and clear queue |
| `!queue` | `!q` | Show the current queue |
| `!clear` | - | Clear the queue (keeps current song) |
| `!loop` | - | Toggle loop mode |
| `!nowplaying` | `!np` | Show current song info |
| `!leave` | `!dc`, `!disconnect` | Leave voice channel |
| `!help` | `!h` | Show help message |

## Auto-Play Feature

The bot automatically detects YouTube links in chat messages. If you're in a voice channel and paste a YouTube link, the bot will automatically join and play it!

To disable auto-play, set `"autoPlay": false` in `config.json`.

## Running as a Service (Linux)

To keep the bot running 24/7, create a systemd service:

```bash
sudo nano /etc/systemd/system/discord-music-bot.service
```

Add this content:
```ini
[Unit]
Description=Discord YouTube Music Bot
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/discord-youtube-bot
ExecStart=/usr/bin/node index.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable discord-music-bot
sudo systemctl start discord-music-bot

# Check status
sudo systemctl status discord-music-bot

# View logs
journalctl -u discord-music-bot -f
```

## Troubleshooting

### "Cannot find module" errors
```bash
rm -rf node_modules package-lock.json
npm install
```

### Bot doesn't play audio
- Make sure FFmpeg is installed: `ffmpeg -version`
- Check if the bot has Connect and Speak permissions in the voice channel

### "This video is unavailable"
- Some videos are region-locked or age-restricted
- Try a different video

### Bot disconnects randomly
- Check your internet connection
- The bot auto-disconnects after 5 minutes of inactivity

## License

MIT License
