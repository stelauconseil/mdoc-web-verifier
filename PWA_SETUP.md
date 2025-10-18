# PWA Setup Guide

This application is now configured as a **Progressive Web App (PWA)**, which means users can install it on their devices for a native app-like experience.

## Features Added

### ✅ Core PWA Components

1. **Web App Manifest** (`manifest.json`)

   - App name, icons, and theme colors
   - Standalone display mode (fullscreen without browser UI)
   - Orientation preferences
   - App shortcuts

2. **Service Worker** (`sw.js`)

   - Offline functionality
   - Cache management for faster loading
   - Background sync capabilities
   - Automatic updates with notifications

3. **Installation Prompt**

   - Custom install banner for better UX
   - Dismissible with 7-day cooldown
   - Tracks installation success

4. **Update Notifications**
   - Automatic detection of new versions
   - User-friendly update prompts
   - Seamless refresh on update

## Installation

### For End Users

#### Desktop (Chrome/Edge)

1. Visit the website over HTTPS
2. Look for the install icon in the address bar (⊕ or 💻)
3. Click "Install" when prompted
4. The app will open in a standalone window

#### Mobile (iOS/Android)

1. Visit the website in Safari (iOS) or Chrome (Android)
2. Tap the share button
3. Select "Add to Home Screen"
4. The app icon will appear on your home screen

### For Developers

#### Generate Icons

Run the icon generation script:

```bash
./generate-icons.sh
```

This will convert the SVG icons to PNG format. Requirements:

- **macOS**: `brew install librsvg`
- **Ubuntu/Debian**: `sudo apt-get install librsvg2-bin`

Alternatively, use an online converter to create:

- `icon-192.png` (192×192px)
- `icon-512.png` (512×512px)

#### Test PWA Locally

1. **Serve over HTTPS** (required for Service Worker):

   ```bash
   # Using Caddy (recommended, see README.md)
   caddy file-server --listen :8000

   # Or use Python with HTTPS
   python -m http.server 8000 --bind 127.0.0.1
   ```

2. **Open Chrome DevTools**:

   - Go to Application tab
   - Check "Service Workers" section
   - Verify "Manifest" section
   - Use "Lighthouse" to audit PWA score

3. **Test Installation**:
   - Chrome: Three-dot menu → "Install app..."
   - Edge: Three-dot menu → "Apps" → "Install this site as an app"

#### Service Worker Debugging

```javascript
// Check if Service Worker is active
navigator.serviceWorker.getRegistration().then((reg) => {
  console.log("Service Worker:", reg);
});

// Clear cache and unregister (for testing)
caches.keys().then((names) => {
  names.forEach((name) => caches.delete(name));
});
navigator.serviceWorker.getRegistrations().then((regs) => {
  regs.forEach((reg) => reg.unregister());
});
```

## PWA Features in This App

### Offline Mode

- App shell cached on first visit
- CDN libraries (jsQR, CBOR) cached after first use
- Works without internet for repeat visits
- Network-first strategy for CDN resources

### Update Strategy

- **Cache-first** for app assets (HTML, manifest)
- **Network-first** for CDN libraries
- Automatic cache invalidation on version change
- User notification when updates are available

### Performance Benefits

- Instant loading after first visit
- Reduced bandwidth usage
- Better mobile experience
- Native-like UI (no browser chrome)

### Security Considerations

- HTTPS required for Service Worker
- Web Bluetooth still requires secure context
- Local storage for IACA certificates persists
- No server-side data transmission

## Customization

### Update App Colors

Edit `manifest.json`:

```json
{
  "theme_color": "#your-color",
  "background_color": "#your-color"
}
```

### Modify Cache Strategy

Edit `sw.js` cache names:

```javascript
const CACHE_NAME = "mdoc-reader-v2"; // Increment version
```

### Add More Shortcuts

Edit `manifest.json` shortcuts array:

```json
{
  "shortcuts": [
    {
      "name": "New Shortcut",
      "url": "/#feature",
      "icons": [...]
    }
  ]
}
```

## Testing Checklist

- [ ] HTTPS enabled
- [ ] Service Worker registered successfully
- [ ] App installable (check for install prompt)
- [ ] Icons display correctly (192px and 512px)
- [ ] Offline mode works (disconnect network)
- [ ] Update notifications appear (change cache version)
- [ ] Theme color matches design
- [ ] Standalone display mode works
- [ ] Web Bluetooth still functional when installed

## Browser Support

| Browser | Desktop | Mobile | Notes                                            |
| ------- | ------- | ------ | ------------------------------------------------ |
| Chrome  | ✅      | ✅     | Full support                                     |
| Edge    | ✅      | ✅     | Full support                                     |
| Safari  | ⚠️      | ⚠️     | Limited Service Worker support, no Web Bluetooth |
| Firefox | ⚠️      | ❌     | No Web Bluetooth support                         |
| Brave   | ✅      | ✅     | Full support                                     |

## Lighthouse Audit

Expected PWA score: **90+**

Key metrics:

- ✅ Fast and reliable
- ✅ Installable
- ✅ PWA optimized
- ⚠️ Some features require Web Bluetooth (not universal)

## Troubleshooting

### Service Worker Not Registering

- Ensure HTTPS is enabled
- Check browser console for errors
- Verify `sw.js` is in root directory
- Clear browser cache and reload

### Install Prompt Not Appearing

- Must be served over HTTPS
- User must visit site at least twice
- Must have meaningful interaction
- Some browsers suppress prompt

### Update Not Working

- Increment `CACHE_NAME` in `sw.js`
- Hard refresh (Ctrl+Shift+R / Cmd+Shift+R)
- Unregister old Service Worker in DevTools
- Clear application cache

### Icons Not Displaying

- Ensure PNG files exist (run `generate-icons.sh`)
- Check manifest.json paths are correct
- Icons must be at least 192×192 and 512×512
- Use absolute paths if relative paths fail

## Resources

- [MDN PWA Guide](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps)
- [Web.dev PWA](https://web.dev/progressive-web-apps/)
- [Service Worker API](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)
- [Web App Manifest](https://developer.mozilla.org/en-US/docs/Web/Manifest)

## License

Same as parent project.
