# Phase 3: aTox Android Integration

**Duration**: 4-6 weeks  
**Goal**: Integrate modified c-toxcore into aTox with security UI  
**Prerequisites**: Phase 2 complete (handshake working)

## Overview

Phase 3 bridges the native PQ-capable c-toxcore to the aTox Android app:
1. Cross-compile c-toxcore + libsodium for Android ABIs
2. Update tox4j bindings
3. Add security status UI components
4. Implement user preferences for PQ policy

## Build System Setup

### 1.1 Directory Structure

```
aqTox-PQ/
├── app/                          # aTox Android app (Kotlin)
├── domain/                       # Domain layer
├── core/                         # Core utilities
├── native/
│   ├── libsodium/               # Submodule: libsodium with ML-KEM
│   ├── c-toxcore/               # Submodule: Modified c-toxcore
│   └── tox4j/                   # Submodule: Modified JNI bindings
├── scripts/
│   ├── build-native.sh          # Master build script
│   ├── build-libsodium.sh       # libsodium for Android
│   └── build-toxcore.sh         # c-toxcore for Android
└── gradle/
    └── native-libs.gradle       # Gradle integration
```

### 1.2 Android ABIs to Support

| ABI | Architecture | Devices |
|-----|--------------|---------|
| `arm64-v8a` | ARM 64-bit | Modern phones (90%+ of market) |
| `armeabi-v7a` | ARM 32-bit | Older devices |
| `x86_64` | x86 64-bit | Emulators, ChromeOS |
| `x86` | x86 32-bit | Old emulators |

### 1.3 Build Script: libsodium

```bash
#!/bin/bash
# scripts/build-libsodium.sh

set -e

SODIUM_VERSION="master"  # Or specific tag with ML-KEM
ANDROID_NDK="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/25.2.9519653}"
MIN_SDK=26

ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")
OUTPUT_DIR="$(pwd)/native/prebuilt"

# Clone if not present
if [ ! -d "native/libsodium" ]; then
    git clone https://github.com/jedisct1/libsodium.git native/libsodium
fi

cd native/libsodium
git checkout $SODIUM_VERSION
./autogen.sh

for ABI in "${ABIS[@]}"; do
    echo "Building libsodium for $ABI..."
    
    case $ABI in
        arm64-v8a)
            HOST="aarch64-linux-android"
            ARCH="arm64"
            ;;
        armeabi-v7a)
            HOST="armv7a-linux-androideabi"
            ARCH="arm"
            ;;
        x86_64)
            HOST="x86_64-linux-android"
            ARCH="x86_64"
            ;;
        x86)
            HOST="i686-linux-android"
            ARCH="x86"
            ;;
    esac
    
    TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64"
    export CC="$TOOLCHAIN/bin/${HOST}${MIN_SDK}-clang"
    export CXX="$TOOLCHAIN/bin/${HOST}${MIN_SDK}-clang++"
    export AR="$TOOLCHAIN/bin/llvm-ar"
    export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
    
    ./configure \
        --host=$HOST \
        --prefix="$OUTPUT_DIR/$ABI" \
        --disable-shared \
        --enable-static \
        --disable-pie \
        CFLAGS="-Os -fPIC"
    
    make -j$(nproc)
    make install
    make clean
done

echo "libsodium build complete for all ABIs"
```

### 1.4 Build Script: c-toxcore

```bash
#!/bin/bash
# scripts/build-toxcore.sh

set -e

ANDROID_NDK="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/25.2.9519653}"
MIN_SDK=26
OUTPUT_DIR="$(pwd)/native/prebuilt"
SODIUM_PREFIX="$OUTPUT_DIR"

ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")

cd native/c-toxcore

for ABI in "${ABIS[@]}"; do
    echo "Building c-toxcore for $ABI..."
    
    BUILD_DIR="build-$ABI"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI=$ABI \
        -DANDROID_PLATFORM=android-$MIN_SDK \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TOXAV=OFF \
        -DBOOTSTRAP_DAEMON=OFF \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        -DLIBSODIUM_INCLUDE_DIR="$SODIUM_PREFIX/$ABI/include" \
        -DLIBSODIUM_LIBRARY="$SODIUM_PREFIX/$ABI/lib/libsodium.a"
    
    make -j$(nproc)
    
    # Copy outputs
    mkdir -p "$OUTPUT_DIR/$ABI/lib"
    cp libtoxcore.a "$OUTPUT_DIR/$ABI/lib/"
    
    cd ..
    rm -rf "$BUILD_DIR"
done

echo "c-toxcore build complete for all ABIs"
```

### 1.5 Build Script: tox4j

```bash
#!/bin/bash
# scripts/build-tox4j.sh

set -e

OUTPUT_DIR="$(pwd)/native/prebuilt"
ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")

cd native/tox4j

for ABI in "${ABIS[@]}"; do
    echo "Building tox4j for $ABI..."
    
    # tox4j has its own build system
    ./scripts/build-$ABI-linux-android -j$(nproc) release
    
    # Copy JNI library
    mkdir -p "$OUTPUT_DIR/$ABI/lib"
    find . -name "libtox4j-c.so" -path "*$ABI*" -exec cp {} "$OUTPUT_DIR/$ABI/lib/" \;
done

echo "tox4j build complete for all ABIs"
```

### 1.6 Gradle Integration

```groovy
// native/native-libs.gradle

android {
    sourceSets {
        main {
            jniLibs.srcDirs = ['native/prebuilt']
        }
    }
}

// Task to build native libraries
task buildNativeLibs(type: Exec) {
    workingDir rootProject.projectDir
    commandLine './scripts/build-native.sh'
}

// Ensure native libs are built before compiling
preBuild.dependsOn buildNativeLibs
```

## tox4j Kotlin API Extensions

### 2.1 Add Security Status Enum

```kotlin
// tox4j/src/main/kotlin/im/tox/tox4j/core/enums/ToxConnectionSecurity.kt

package im.tox.tox4j.core.enums

enum class ToxConnectionSecurity(val value: Int) {
    UNKNOWN(0),
    CLASSICAL(1),
    HYBRID(2);
    
    companion object {
        fun fromValue(value: Int): ToxConnectionSecurity {
            return values().find { it.value == value } ?: UNKNOWN
        }
    }
}
```

### 2.2 Extend ToxCore Interface

```kotlin
// tox4j/src/main/kotlin/im/tox/tox4j/core/ToxCore.kt

interface ToxCore {
    // ... existing methods ...
    
    /**
     * Get the security level of a friend connection.
     * 
     * @param friendNumber The friend to query
     * @return The security level of the connection
     * @throws ToxFriendQueryException on error
     */
    fun friendGetConnectionSecurity(friendNumber: Int): ToxConnectionSecurity
    
    /**
     * Check if this Tox instance has PQ capability.
     * 
     * @return true if post-quantum algorithms are available
     */
    fun selfGetPqCapable(): Boolean
}
```

### 2.3 Implement in ToxCoreImpl

```kotlin
// tox4j/src/main/kotlin/im/tox/tox4j/core/ToxCoreImpl.kt

class ToxCoreImpl : ToxCore {
    // ... existing implementation ...
    
    override fun friendGetConnectionSecurity(friendNumber: Int): ToxConnectionSecurity {
        val value = toxFriendGetConnectionSecurity(friendNumber)
        return ToxConnectionSecurity.fromValue(value)
    }
    
    override fun selfGetPqCapable(): Boolean {
        return toxSelfGetPqCapable()
    }
    
    // Native methods
    private external fun toxFriendGetConnectionSecurity(friendNumber: Int): Int
    private external fun toxSelfGetPqCapable(): Boolean
}
```

## aTox Domain Layer Updates

### 3.1 Extend Contact Model

```kotlin
// domain/src/main/kotlin/ltd/evilcorp/domain/model/Contact.kt

data class Contact(
    val publicKey: String,
    val name: String,
    val statusMessage: String,
    val status: UserStatus,
    val connectionStatus: ConnectionStatus,
    val connectionSecurity: ConnectionSecurity,  // NEW
    // ... other fields
)

enum class ConnectionSecurity {
    UNKNOWN,
    CLASSICAL,
    HYBRID;
    
    companion object {
        fun fromTox(toxSecurity: ToxConnectionSecurity): ConnectionSecurity {
            return when (toxSecurity) {
                ToxConnectionSecurity.UNKNOWN -> UNKNOWN
                ToxConnectionSecurity.CLASSICAL -> CLASSICAL
                ToxConnectionSecurity.HYBRID -> HYBRID
            }
        }
    }
}
```

### 3.2 Update Tox Service

```kotlin
// domain/src/main/kotlin/ltd/evilcorp/domain/tox/ToxService.kt

class ToxService @Inject constructor(
    private val tox: Tox,
    // ... other dependencies
) {
    // ... existing code ...
    
    fun getFriendConnectionSecurity(friendNumber: Int): ConnectionSecurity {
        return try {
            val toxSecurity = tox.friendGetConnectionSecurity(friendNumber)
            ConnectionSecurity.fromTox(toxSecurity)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get connection security", e)
            ConnectionSecurity.UNKNOWN
        }
    }
    
    fun isPqCapable(): Boolean {
        return tox.selfGetPqCapable()
    }
}
```

### 3.3 Update Contact Repository

```kotlin
// domain/src/main/kotlin/ltd/evilcorp/domain/feature/ContactRepository.kt

class ContactRepository @Inject constructor(
    private val toxService: ToxService,
    private val contactDao: ContactDao
) {
    // Update contact with security status on connection change
    fun updateConnectionStatus(friendNumber: Int, status: ConnectionStatus) {
        val security = if (status == ConnectionStatus.ONLINE) {
            toxService.getFriendConnectionSecurity(friendNumber)
        } else {
            ConnectionSecurity.UNKNOWN
        }
        
        contactDao.updateConnectionInfo(friendNumber, status, security)
    }
}
```

## aTox UI Updates

### 4.1 Security Badge Component

```kotlin
// app/src/main/kotlin/ltd/evilcorp/atox/ui/components/SecurityBadge.kt

@Composable
fun SecurityBadge(
    security: ConnectionSecurity,
    modifier: Modifier = Modifier
) {
    val (icon, color, description) = when (security) {
        ConnectionSecurity.HYBRID -> Triple(
            Icons.Filled.Shield,
            Color(0xFF4CAF50),  // Green
            "Quantum-Resistant"
        )
        ConnectionSecurity.CLASSICAL -> Triple(
            Icons.Filled.Lock,
            Color(0xFFFFC107),  // Amber
            "Classical Encryption"
        )
        ConnectionSecurity.UNKNOWN -> Triple(
            Icons.Filled.HelpOutline,
            Color.Gray,
            "Unknown"
        )
    }
    
    Row(
        modifier = modifier
            .background(color.copy(alpha = 0.1f), RoundedCornerShape(4.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = description,
            tint = color,
            modifier = Modifier.size(16.dp)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = if (security == ConnectionSecurity.HYBRID) "PQ" else "Classic",
            style = MaterialTheme.typography.labelSmall,
            color = color
        )
    }
}
```

### 4.2 Update Chat Header

```kotlin
// app/src/main/kotlin/ltd/evilcorp/atox/ui/chat/ChatScreen.kt

@Composable
fun ChatHeader(
    contact: Contact,
    onBackClick: () -> Unit
) {
    TopAppBar(
        title = {
            Column {
                Text(contact.name)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    ConnectionStatusIndicator(contact.connectionStatus)
                    if (contact.connectionStatus == ConnectionStatus.ONLINE) {
                        Spacer(modifier = Modifier.width(8.dp))
                        SecurityBadge(contact.connectionSecurity)
                    }
                }
            }
        },
        navigationIcon = {
            IconButton(onClick = onBackClick) {
                Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
            }
        }
    )
}
```

### 4.3 Update Contact List Item

```kotlin
// app/src/main/kotlin/ltd/evilcorp/atox/ui/contactlist/ContactListItem.kt

@Composable
fun ContactListItem(
    contact: Contact,
    onClick: () -> Unit
) {
    ListItem(
        headlineContent = { Text(contact.name) },
        supportingContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(contact.statusMessage.take(30))
                if (contact.connectionStatus == ConnectionStatus.ONLINE) {
                    Spacer(modifier = Modifier.width(8.dp))
                    SecurityBadge(
                        security = contact.connectionSecurity,
                        modifier = Modifier.alpha(0.8f)
                    )
                }
            }
        },
        leadingContent = {
            Avatar(contact.publicKey, contact.name)
        },
        trailingContent = {
            ConnectionStatusDot(contact.connectionStatus)
        },
        modifier = Modifier.clickable(onClick = onClick)
    )
}
```

### 4.4 Security Info Dialog

```kotlin
// app/src/main/kotlin/ltd/evilcorp/atox/ui/chat/SecurityInfoDialog.kt

@Composable
fun SecurityInfoDialog(
    security: ConnectionSecurity,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Connection Security") },
        text = {
            Column {
                when (security) {
                    ConnectionSecurity.HYBRID -> {
                        Text(
                            "This connection uses hybrid post-quantum encryption.",
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Your messages are protected by both classical (X25519) " +
                            "and post-quantum (ML-KEM-768) cryptography. This provides " +
                            "protection against future quantum computer attacks."
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row {
                            Icon(
                                Icons.Filled.Check,
                                contentDescription = null,
                                tint = Color(0xFF4CAF50)
                            )
                            Text(" Forward secrecy")
                        }
                        Row {
                            Icon(
                                Icons.Filled.Check,
                                contentDescription = null,
                                tint = Color(0xFF4CAF50)
                            )
                            Text(" Quantum-resistant key exchange")
                        }
                    }
                    ConnectionSecurity.CLASSICAL -> {
                        Text(
                            "This connection uses classical encryption.",
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Your messages are protected by X25519 key exchange. " +
                            "This is secure against current computers but may be " +
                            "vulnerable to future quantum computers."
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "The other user's client may not support post-quantum " +
                            "encryption. Consider asking them to upgrade to aqTox-PQ.",
                            color = Color(0xFFFFC107)
                        )
                    }
                    ConnectionSecurity.UNKNOWN -> {
                        Text("Connection security status is unknown.")
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("OK")
            }
        }
    )
}
```

### 4.5 Settings: PQ Policy

```kotlin
// app/src/main/kotlin/ltd/evilcorp/atox/ui/settings/SecuritySettingsScreen.kt

@Composable
fun SecuritySettingsScreen(
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val isPqCapable by viewModel.isPqCapable.collectAsState()
    val pqPolicy by viewModel.pqPolicy.collectAsState()
    
    Column(modifier = Modifier.padding(16.dp)) {
        Text(
            "Post-Quantum Security",
            style = MaterialTheme.typography.headlineSmall
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // PQ Capability Status
        Card(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    if (isPqCapable) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                    contentDescription = null,
                    tint = if (isPqCapable) Color(0xFF4CAF50) else Color.Red
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column {
                    Text(
                        if (isPqCapable) "PQ Algorithms Available" 
                        else "PQ Not Available",
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        if (isPqCapable) "ML-KEM-768 supported"
                        else "Update libsodium required",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // PQ Policy Selection
        Text(
            "Connection Policy",
            style = MaterialTheme.typography.titleMedium
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        PqPolicyOption(
            title = "Prefer PQ (Recommended)",
            description = "Use quantum-resistant encryption when available, " +
                         "fall back to classical otherwise.",
            selected = pqPolicy == PqPolicy.PREFER,
            onClick = { viewModel.setPqPolicy(PqPolicy.PREFER) }
        )
        
        PqPolicyOption(
            title = "Require PQ",
            description = "Only connect to peers with PQ support. " +
                         "Connections to legacy clients will be blocked.",
            selected = pqPolicy == PqPolicy.REQUIRE,
            onClick = { viewModel.setPqPolicy(PqPolicy.REQUIRE) }
        )
        
        PqPolicyOption(
            title = "Classical Only",
            description = "Disable PQ encryption. Not recommended.",
            selected = pqPolicy == PqPolicy.DISABLED,
            onClick = { viewModel.setPqPolicy(PqPolicy.DISABLED) }
        )
    }
}

@Composable
fun PqPolicyOption(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) 
                MaterialTheme.colorScheme.primaryContainer
            else 
                MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(title, fontWeight = FontWeight.Medium)
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
```

## Database Schema Updates

### 5.1 Migration

```kotlin
// core/src/main/kotlin/ltd/evilcorp/core/db/Migrations.kt

val MIGRATION_X_Y = object : Migration(X, Y) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL("""
            ALTER TABLE contacts 
            ADD COLUMN connection_security INTEGER NOT NULL DEFAULT 0
        """)
    }
}
```

### 5.2 Updated DAO

```kotlin
// core/src/main/kotlin/ltd/evilcorp/core/db/ContactDao.kt

@Dao
interface ContactDao {
    @Query("""
        UPDATE contacts 
        SET connection_status = :status, connection_security = :security 
        WHERE public_key = :publicKey
    """)
    suspend fun updateConnectionInfo(
        publicKey: String, 
        status: Int, 
        security: Int
    )
    
    // ... existing methods ...
}
```

## Phase 3 Deliverables Checklist

- [ ] Native build scripts for all Android ABIs
- [ ] libsodium with ML-KEM built for Android
- [ ] c-toxcore built for Android
- [ ] tox4j JNI library built for Android
- [ ] Gradle integration for native builds
- [ ] tox4j Kotlin API extensions
- [ ] Domain layer security model
- [ ] SecurityBadge UI component
- [ ] Chat header with security indicator
- [ ] Contact list with security badges
- [ ] Security info dialog
- [ ] PQ policy settings screen
- [ ] Database schema migration
- [ ] App compiles and runs on device

## Next: Phase 4

With the full stack integrated, Phase 4 focuses on comprehensive testing:
- Unit tests for all layers
- Integration tests
- Interoperability testing with legacy clients
- Security review preparation
