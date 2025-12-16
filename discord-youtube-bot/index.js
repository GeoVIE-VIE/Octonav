const {
  Client,
  GatewayIntentBits,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
} = require("discord.js");
const {
  joinVoiceChannel,
  createAudioPlayer,
  createAudioResource,
  AudioPlayerStatus,
  VoiceConnectionStatus,
  entersState,
  getVoiceConnection,
} = require("@discordjs/voice");
const play = require("play-dl");
const fs = require("fs");
const path = require("path");

// Load configuration
const configPath = path.join(__dirname, "config.json");
if (!fs.existsSync(configPath)) {
  console.error("❌ config.json not found! Copy config.example.json to config.json and add your bot token.");
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const PREFIX = config.prefix || "!";

// Create Discord client with necessary intents
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildVoiceStates,
  ],
});

// Music queue per server
const queues = new Map();

// Queue structure for each guild
function createQueue() {
  return {
    songs: [],
    connection: null,
    player: createAudioPlayer(),
    playing: false,
    loop: false,
    volume: 100,
  };
}

// Get or create queue for a guild
function getQueue(guildId) {
  if (!queues.has(guildId)) {
    queues.set(guildId, createQueue());
  }
  return queues.get(guildId);
}

// YouTube URL patterns
const YOUTUBE_REGEX = /(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/;
const YOUTUBE_PLAYLIST_REGEX = /(?:https?:\/\/)?(?:www\.)?youtube\.com\/playlist\?list=([a-zA-Z0-9_-]+)/;

// Extract YouTube URLs from message
function extractYouTubeUrls(content) {
  const urls = [];
  const words = content.split(/\s+/);
  for (const word of words) {
    if (YOUTUBE_REGEX.test(word) || YOUTUBE_PLAYLIST_REGEX.test(word)) {
      urls.push(word);
    }
  }
  return urls;
}

// Get video info from YouTube
async function getVideoInfo(url) {
  try {
    if (play.yt_validate(url) === "playlist") {
      const playlist = await play.playlist_info(url, { incomplete: true });
      const videos = await playlist.all_videos();
      return videos.map((video) => ({
        title: video.title,
        url: video.url,
        duration: video.durationRaw,
        thumbnail: video.thumbnails[0]?.url,
        channel: video.channel?.name || "Unknown",
      }));
    } else {
      const info = await play.video_info(url);
      return [
        {
          title: info.video_details.title,
          url: info.video_details.url,
          duration: info.video_details.durationRaw,
          thumbnail: info.video_details.thumbnails[0]?.url,
          channel: info.video_details.channel?.name || "Unknown",
        },
      ];
    }
  } catch (error) {
    console.error("Error getting video info:", error);
    return null;
  }
}

// Create audio stream from YouTube URL
async function createStream(url) {
  try {
    const stream = await play.stream(url);
    return createAudioResource(stream.stream, {
      inputType: stream.type,
    });
  } catch (error) {
    console.error("Error creating stream:", error);
    return null;
  }
}

// Play next song in queue
async function playNext(guildId, textChannel) {
  const queue = getQueue(guildId);

  if (queue.songs.length === 0) {
    queue.playing = false;
    // Disconnect after 5 minutes of inactivity
    setTimeout(() => {
      const currentQueue = getQueue(guildId);
      if (!currentQueue.playing && currentQueue.songs.length === 0) {
        const connection = getVoiceConnection(guildId);
        if (connection) {
          connection.destroy();
          queues.delete(guildId);
        }
      }
    }, 5 * 60 * 1000);
    return;
  }

  const song = queue.songs[0];
  const resource = await createStream(song.url);

  if (!resource) {
    textChannel.send(`❌ Failed to play: **${song.title}**`);
    queue.songs.shift();
    playNext(guildId, textChannel);
    return;
  }

  queue.player.play(resource);
  queue.playing = true;

  // Create now playing embed
  const embed = new EmbedBuilder()
    .setColor(0xff0000)
    .setTitle("🎵 Now Playing")
    .setDescription(`**[${song.title}](${song.url})**`)
    .addFields(
      { name: "Duration", value: song.duration || "Unknown", inline: true },
      { name: "Channel", value: song.channel || "Unknown", inline: true },
      { name: "Requested by", value: song.requestedBy || "Unknown", inline: true }
    )
    .setThumbnail(song.thumbnail || null)
    .setTimestamp();

  // Create control buttons
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("pause")
      .setLabel("⏸️ Pause")
      .setStyle(ButtonStyle.Secondary),
    new ButtonBuilder()
      .setCustomId("skip")
      .setLabel("⏭️ Skip")
      .setStyle(ButtonStyle.Primary),
    new ButtonBuilder()
      .setCustomId("stop")
      .setLabel("⏹️ Stop")
      .setStyle(ButtonStyle.Danger),
    new ButtonBuilder()
      .setCustomId("queue")
      .setLabel("📜 Queue")
      .setStyle(ButtonStyle.Secondary)
  );

  textChannel.send({ embeds: [embed], components: [row] });
}

// Handle audio player state changes
function setupPlayerEvents(guildId, textChannel) {
  const queue = getQueue(guildId);

  queue.player.on(AudioPlayerStatus.Idle, () => {
    if (queue.loop && queue.songs.length > 0) {
      // Move current song to end of queue for loop
      queue.songs.push(queue.songs.shift());
    } else {
      queue.songs.shift();
    }
    playNext(guildId, textChannel);
  });

  queue.player.on("error", (error) => {
    console.error("Player error:", error);
    queue.songs.shift();
    playNext(guildId, textChannel);
  });
}

// Join voice channel
async function joinChannel(member, guild) {
  const voiceChannel = member.voice.channel;
  if (!voiceChannel) {
    return { success: false, message: "❌ You need to be in a voice channel!" };
  }

  const permissions = voiceChannel.permissionsFor(guild.members.me);
  if (!permissions.has("Connect") || !permissions.has("Speak")) {
    return {
      success: false,
      message: "❌ I need permissions to join and speak in your voice channel!",
    };
  }

  try {
    const connection = joinVoiceChannel({
      channelId: voiceChannel.id,
      guildId: guild.id,
      adapterCreator: guild.voiceAdapterCreator,
    });

    await entersState(connection, VoiceConnectionStatus.Ready, 30_000);

    const queue = getQueue(guild.id);
    queue.connection = connection;
    connection.subscribe(queue.player);

    return { success: true, connection };
  } catch (error) {
    console.error("Error joining channel:", error);
    return { success: false, message: "❌ Failed to join voice channel!" };
  }
}

// Bot ready event
client.once("ready", () => {
  console.log(`✅ Bot is online as ${client.user.tag}`);
  console.log(`📡 Serving ${client.guilds.cache.size} server(s)`);
  console.log(`🎵 Prefix: ${PREFIX}`);
  console.log("────────────────────────────────────");
  client.user.setActivity("YouTube | !help", { type: 2 }); // Listening
});

// Message event - handle commands and auto-detect YouTube links
client.on("messageCreate", async (message) => {
  if (message.author.bot) return;

  // Auto-detect YouTube links in any message
  const youtubeUrls = extractYouTubeUrls(message.content);
  if (youtubeUrls.length > 0 && !message.content.startsWith(PREFIX)) {
    // Check if user is in a voice channel
    if (!message.member.voice.channel) {
      return; // Silently ignore if user is not in voice channel
    }

    // Check if auto-play is enabled (can be toggled)
    const queue = getQueue(message.guild.id);
    if (config.autoPlay !== false) {
      for (const url of youtubeUrls) {
        await handlePlay(message, url);
      }
      return;
    }
  }

  // Command handling
  if (!message.content.startsWith(PREFIX)) return;

  const args = message.content.slice(PREFIX.length).trim().split(/ +/);
  const command = args.shift().toLowerCase();

  switch (command) {
    case "play":
    case "p":
      const query = args.join(" ");
      if (!query) {
        return message.reply("❌ Please provide a YouTube URL or search query!");
      }
      await handlePlay(message, query);
      break;

    case "skip":
    case "s":
      handleSkip(message);
      break;

    case "stop":
      handleStop(message);
      break;

    case "pause":
      handlePause(message);
      break;

    case "resume":
    case "r":
      handleResume(message);
      break;

    case "queue":
    case "q":
      handleShowQueue(message);
      break;

    case "clear":
      handleClear(message);
      break;

    case "loop":
      handleLoop(message);
      break;

    case "nowplaying":
    case "np":
      handleNowPlaying(message);
      break;

    case "leave":
    case "disconnect":
    case "dc":
      handleLeave(message);
      break;

    case "help":
    case "h":
      handleHelp(message);
      break;

    default:
      // Check if it's a YouTube URL as the command
      if (YOUTUBE_REGEX.test(command) || YOUTUBE_PLAYLIST_REGEX.test(command)) {
        await handlePlay(message, command);
      }
      break;
  }
});

// Handle play command
async function handlePlay(message, query) {
  const joinResult = await joinChannel(message.member, message.guild);
  if (!joinResult.success) {
    return message.reply(joinResult.message);
  }

  const queue = getQueue(message.guild.id);

  // Check if query is a URL or search term
  let url = query;
  if (!YOUTUBE_REGEX.test(query) && !YOUTUBE_PLAYLIST_REGEX.test(query)) {
    // Search YouTube
    try {
      const searched = await play.search(query, { limit: 1 });
      if (searched.length === 0) {
        return message.reply("❌ No results found!");
      }
      url = searched[0].url;
    } catch (error) {
      console.error("Search error:", error);
      return message.reply("❌ Failed to search YouTube!");
    }
  }

  // Get video info
  const videos = await getVideoInfo(url);
  if (!videos || videos.length === 0) {
    return message.reply("❌ Failed to get video information!");
  }

  // Add to queue
  for (const video of videos) {
    queue.songs.push({
      ...video,
      requestedBy: message.author.username,
    });
  }

  if (videos.length === 1) {
    if (queue.playing) {
      const embed = new EmbedBuilder()
        .setColor(0x00ff00)
        .setTitle("✅ Added to Queue")
        .setDescription(`**[${videos[0].title}](${videos[0].url})**`)
        .addFields({ name: "Position in queue", value: `${queue.songs.length}`, inline: true })
        .setThumbnail(videos[0].thumbnail || null);
      message.reply({ embeds: [embed] });
    }
  } else {
    message.reply(`✅ Added **${videos.length}** songs from playlist to queue!`);
  }

  // Start playing if not already
  if (!queue.playing) {
    setupPlayerEvents(message.guild.id, message.channel);
    playNext(message.guild.id, message.channel);
  }
}

// Handle skip command
function handleSkip(message) {
  const queue = getQueue(message.guild.id);
  if (!queue.playing || queue.songs.length === 0) {
    return message.reply("❌ Nothing is playing!");
  }
  queue.player.stop();
  message.reply("⏭️ Skipped!");
}

// Handle stop command
function handleStop(message) {
  const queue = getQueue(message.guild.id);
  queue.songs = [];
  queue.playing = false;
  queue.player.stop();

  const connection = getVoiceConnection(message.guild.id);
  if (connection) {
    connection.destroy();
  }
  queues.delete(message.guild.id);
  message.reply("⏹️ Stopped and cleared the queue!");
}

// Handle pause command
function handlePause(message) {
  const queue = getQueue(message.guild.id);
  if (!queue.playing) {
    return message.reply("❌ Nothing is playing!");
  }
  queue.player.pause();
  message.reply("⏸️ Paused!");
}

// Handle resume command
function handleResume(message) {
  const queue = getQueue(message.guild.id);
  queue.player.unpause();
  message.reply("▶️ Resumed!");
}

// Handle show queue command
function handleShowQueue(message) {
  const queue = getQueue(message.guild.id);
  if (queue.songs.length === 0) {
    return message.reply("📜 The queue is empty!");
  }

  const queueList = queue.songs
    .slice(0, 10)
    .map((song, index) => `${index + 1}. **${song.title}** (${song.duration || "Unknown"})`)
    .join("\n");

  const embed = new EmbedBuilder()
    .setColor(0x0099ff)
    .setTitle("📜 Music Queue")
    .setDescription(queueList)
    .setFooter({
      text: `${queue.songs.length} song(s) in queue | Loop: ${queue.loop ? "ON" : "OFF"}`,
    });

  if (queue.songs.length > 10) {
    embed.addFields({ name: "And more...", value: `+${queue.songs.length - 10} more songs` });
  }

  message.reply({ embeds: [embed] });
}

// Handle clear command
function handleClear(message) {
  const queue = getQueue(message.guild.id);
  const currentSong = queue.songs[0];
  queue.songs = currentSong ? [currentSong] : [];
  message.reply("🗑️ Queue cleared! (Keeping current song)");
}

// Handle loop command
function handleLoop(message) {
  const queue = getQueue(message.guild.id);
  queue.loop = !queue.loop;
  message.reply(`🔁 Loop is now **${queue.loop ? "ON" : "OFF"}**`);
}

// Handle now playing command
function handleNowPlaying(message) {
  const queue = getQueue(message.guild.id);
  if (!queue.playing || queue.songs.length === 0) {
    return message.reply("❌ Nothing is playing!");
  }

  const song = queue.songs[0];
  const embed = new EmbedBuilder()
    .setColor(0xff0000)
    .setTitle("🎵 Now Playing")
    .setDescription(`**[${song.title}](${song.url})**`)
    .addFields(
      { name: "Duration", value: song.duration || "Unknown", inline: true },
      { name: "Channel", value: song.channel || "Unknown", inline: true },
      { name: "Requested by", value: song.requestedBy || "Unknown", inline: true }
    )
    .setThumbnail(song.thumbnail || null);

  message.reply({ embeds: [embed] });
}

// Handle leave command
function handleLeave(message) {
  const connection = getVoiceConnection(message.guild.id);
  if (connection) {
    connection.destroy();
    queues.delete(message.guild.id);
    message.reply("👋 Disconnected from voice channel!");
  } else {
    message.reply("❌ I'm not in a voice channel!");
  }
}

// Handle help command
function handleHelp(message) {
  const embed = new EmbedBuilder()
    .setColor(0x0099ff)
    .setTitle("🎵 YouTube Music Bot - Commands")
    .setDescription("Play YouTube audio in your voice channel!\n\n**Just paste a YouTube link and I'll play it!**")
    .addFields(
      {
        name: "🎶 Playback",
        value: `\`${PREFIX}play <url/search>\` - Play a song\n\`${PREFIX}pause\` - Pause playback\n\`${PREFIX}resume\` - Resume playback\n\`${PREFIX}skip\` - Skip current song\n\`${PREFIX}stop\` - Stop and clear queue`,
        inline: false,
      },
      {
        name: "📜 Queue",
        value: `\`${PREFIX}queue\` - Show the queue\n\`${PREFIX}clear\` - Clear the queue\n\`${PREFIX}loop\` - Toggle loop mode\n\`${PREFIX}nowplaying\` - Show current song`,
        inline: false,
      },
      {
        name: "🔧 Other",
        value: `\`${PREFIX}leave\` - Leave voice channel\n\`${PREFIX}help\` - Show this message`,
        inline: false,
      },
      {
        name: "✨ Auto-Play",
        value: "Just paste a YouTube link in chat while in a voice channel, and I'll automatically play it!",
        inline: false,
      }
    )
    .setFooter({ text: `Prefix: ${PREFIX}` });

  message.reply({ embeds: [embed] });
}

// Button interaction handler
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isButton()) return;

  const queue = getQueue(interaction.guild.id);

  switch (interaction.customId) {
    case "pause":
      if (queue.player.state.status === AudioPlayerStatus.Playing) {
        queue.player.pause();
        await interaction.reply({ content: "⏸️ Paused!", ephemeral: true });
      } else {
        queue.player.unpause();
        await interaction.reply({ content: "▶️ Resumed!", ephemeral: true });
      }
      break;

    case "skip":
      if (queue.songs.length > 0) {
        queue.player.stop();
        await interaction.reply({ content: "⏭️ Skipped!", ephemeral: true });
      } else {
        await interaction.reply({ content: "❌ Nothing to skip!", ephemeral: true });
      }
      break;

    case "stop":
      queue.songs = [];
      queue.playing = false;
      queue.player.stop();
      const connection = getVoiceConnection(interaction.guild.id);
      if (connection) {
        connection.destroy();
      }
      queues.delete(interaction.guild.id);
      await interaction.reply({ content: "⏹️ Stopped!", ephemeral: true });
      break;

    case "queue":
      if (queue.songs.length === 0) {
        await interaction.reply({ content: "📜 Queue is empty!", ephemeral: true });
      } else {
        const queueList = queue.songs
          .slice(0, 5)
          .map((song, i) => `${i + 1}. ${song.title}`)
          .join("\n");
        await interaction.reply({
          content: `📜 **Queue:**\n${queueList}${queue.songs.length > 5 ? `\n...and ${queue.songs.length - 5} more` : ""}`,
          ephemeral: true,
        });
      }
      break;
  }
});

// Error handling
client.on("error", (error) => {
  console.error("Discord client error:", error);
});

process.on("unhandledRejection", (error) => {
  console.error("Unhandled promise rejection:", error);
});

// Login to Discord
client.login(config.token);
