package com.example.lock.file_manager

import java.io.File
import java.util.ArrayDeque
import java.util.Locale
import java.util.PriorityQueue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.text.iterator

object FileSearchEngine {

    const val DEFAULT_LIMIT = 300
    const val MAX_RESULTS = 500
    const val MAX_ENTRIES = 80000
    const val MAX_DEPTH = 24

    sealed class IndexState {
        object Idle : IndexState()
        data class Indexing(val scanned: Int) : IndexState()
        data class Ready(val count: Int) : IndexState()
    }

    data class IndexedFile(
        val file: File,
        val path: String,
        val name: String,
        val lowerName: String,
        val lowerPath: String,
        val isDirectory: Boolean,
        val extension: String,
        val size: Long,
        val lastModified: Long
    )

    private data class Scored(val entry: IndexedFile, val score: Int)

    @Volatile
    private var snapshot: List<IndexedFile> = emptyList()

    @Volatile
    private var indexedRootPath: String? = null

    private val buildMutex = Mutex()

    private val searchCache = object : LinkedHashMap<String, List<IndexedFile>>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, List<IndexedFile>>): Boolean {
            return size > 64
        }
    }

    private val _indexState = MutableStateFlow<IndexState>(IndexState.Idle)
    val indexState: StateFlow<IndexState> = _indexState

    private val whitespace = Regex("\\s+")

    fun isIndexed(root: File): Boolean {
        return indexedRootPath == root.absolutePath && snapshot.isNotEmpty()
    }

    suspend fun ensureIndexed(root: File) {
        val rootPath = root.absolutePath
        if (indexedRootPath == rootPath && snapshot.isNotEmpty()) return
        buildMutex.withLock {
            if (indexedRootPath == rootPath && snapshot.isNotEmpty()) return
            _indexState.value = IndexState.Indexing(0)
            try {
                val fresh = withContext(Dispatchers.IO) {
                    walkRoot(root) { scanned -> _indexState.value = IndexState.Indexing(scanned) }
                }
                snapshot = fresh
                indexedRootPath = rootPath
                clearCache()
                _indexState.value = IndexState.Ready(fresh.size)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _indexState.value = IndexState.Idle
            }
        }
    }

    suspend fun searchFast(
        root: File,
        rawQuery: String,
        limit: Int = DEFAULT_LIMIT,
        sortMode: String = "DATE"
    ): List<IndexedFile> =
        withContext(Dispatchers.Default) {
            val normalized = normalize(rawQuery)
            if (normalized.isBlank()) return@withContext emptyList()
            ensureIndexed(root)
            val data = snapshot
            if (data.isEmpty()) return@withContext emptyList()
            val cappedLimit = limit.coerceIn(1, MAX_RESULTS)
            val cacheKey = root.absolutePath + "\n" + normalized + "\n" + cappedLimit + "\n" + sortMode
            getCached(cacheKey)?.let { return@withContext it }
            val tokens = normalized.split(' ').filter { it.isNotEmpty() }
            if (tokens.isEmpty()) return@withContext emptyList()
            val compare: (Scored, Scored) -> Int = { a, b -> compareSearch(a, b, sortMode) }
            val prefixHits = collectTop(data, cappedLimit, compare) { entry -> prefixScore(entry, normalized) }
            val result = ArrayList<IndexedFile>(cappedLimit)
            result.addAll(prefixHits)
            if (result.size < cappedLimit) {
                val prefixPaths = prefixHits.map { it.path }.toHashSet()
                val folderExtra = collectTop(data, cappedLimit - result.size, compare) { entry ->
                    if (!entry.isDirectory || prefixPaths.contains(entry.path)) {
                        Int.MAX_VALUE
                    } else {
                        substringScore(entry, tokens)
                    }
                }
                result.addAll(folderExtra)
                if (result.size < cappedLimit && prefixHits.none { !it.isDirectory }) {
                    val fileExtra = collectTop(data, cappedLimit - result.size, compare) { entry ->
                        if (entry.isDirectory || prefixPaths.contains(entry.path)) {
                            Int.MAX_VALUE
                        } else {
                            substringScore(entry, tokens)
                        }
                    }
                    result.addAll(fileExtra)
                }
            }
            putCached(cacheKey, result)
            result
        }

    suspend fun onFileRenamed(oldFile: File, newFile: File) {
        withContext(Dispatchers.IO) {
            buildMutex.withLock {
                val rootPath = indexedRootPath
                if (rootPath == null || snapshot.isEmpty()) return@withLock
                val oldPath = oldFile.absolutePath
                val kept = snapshot.filterNot { it.path == oldPath || it.path.startsWith(oldPath + "/") }
                val added = if (newFile.exists()) {
                    try {
                        walkSubtree(newFile, skipPrefixes(File(rootPath)))
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        emptyList()
                    }
                } else {
                    emptyList()
                }
                snapshot = kept + added
                clearCache()
                _indexState.value = IndexState.Ready(snapshot.size)
            }
        }
    }

    suspend fun onFileDeleted(target: File) {
        withContext(Dispatchers.IO) {
            buildMutex.withLock {
                if (snapshot.isEmpty()) return@withLock
                val dead = target.absolutePath
                snapshot = snapshot.filterNot { it.path == dead || it.path.startsWith(dead + "/") }
                clearCache()
                _indexState.value = IndexState.Ready(snapshot.size)
            }
        }
    }

    fun invalidateIndex() {
        snapshot = emptyList()
        indexedRootPath = null
        clearCache()
        _indexState.value = IndexState.Idle
    }

    private suspend fun collectTop(
        data: List<IndexedFile>,
        limit: Int,
        compare: (Scored, Scored) -> Int,
        score: (IndexedFile) -> Int
    ): List<IndexedFile> {
        val heap = PriorityQueue<Scored>(limit) { a, b -> compare(b, a) }
        var iterations = 0
        for (entry in data) {
            if ((iterations++ and 4095) == 0) currentCoroutineContext().ensureActive()
            val entryScore = score(entry)
            if (entryScore == Int.MAX_VALUE) continue
            val candidate = Scored(entry, entryScore)
            if (heap.size < limit) {
                heap.add(candidate)
            } else {
                val worst = heap.peek()
                if (worst != null && compare(candidate, worst) < 0) {
                    heap.poll()
                    heap.add(candidate)
                }
            }
        }
        return heap.sortedWith { a, b -> compare(a, b) }.map { it.entry }
    }

    private fun prefixScore(entry: IndexedFile, query: String): Int {
        val name = entry.lowerName
        return when {
            name == query -> 0
            name.startsWith(query) -> 1
            else -> Int.MAX_VALUE
        }
    }

    private fun substringScore(entry: IndexedFile, tokens: List<String>): Int {
        var total = 0
        for (token in tokens) {
            val name = entry.lowerName
            val partial = when {
                startsAtWordBoundary(name, token) -> 2
                name.contains(token) -> 3
                entry.lowerPath.contains(token) -> 5
                else -> return Int.MAX_VALUE
            }
            total += partial
        }
        return total
    }

    private fun startsAtWordBoundary(haystack: String, needle: String): Boolean {
        var index = haystack.indexOf(needle, 1)
        while (index > 0) {
            val previous = haystack[index - 1]
            if (previous == ' ' || previous == '/') return true
            index = haystack.indexOf(needle, index + 1)
        }
        return false
    }

    private fun compareSearch(a: Scored, b: Scored, sortMode: String): Int {
        if (a.score != b.score) return a.score.compareTo(b.score)
        val ordered = when (sortMode) {
            "SIZE" -> b.entry.size.compareTo(a.entry.size)
            "DATE" -> b.entry.lastModified.compareTo(a.entry.lastModified)
            else -> a.entry.lowerName.compareTo(b.entry.lowerName)
        }
        if (ordered != 0) return ordered
        val byName = a.entry.lowerName.compareTo(b.entry.lowerName)
        if (byName != 0) return byName
        return a.entry.path.compareTo(b.entry.path)
    }

    private fun normalize(value: String): String {
        val mapped = value.trim().lowercase(Locale.ROOT).replace('\\', '/')
        val sb = StringBuilder(mapped.length)
        for (ch in mapped) {
            when (ch) {
                '_', '-', '.' -> sb.append(' ')
                else -> sb.append(ch)
            }
        }
        return sb.toString().replace(whitespace, " ")
    }

    private suspend fun walkRoot(root: File, onProgress: (Int) -> Unit): List<IndexedFile> {
        val out = ArrayList<IndexedFile>(4096)
        val skip = skipPrefixes(root)
        val stack = ArrayDeque<Pair<File, Int>>()
        val seenDirs = HashSet<String>()
        stack.add(root to 0)
        var ops = 0
        while (stack.isNotEmpty()) {
            if ((ops++ and 31) == 0) currentCoroutineContext().ensureActive()
            val (current, depth) = stack.removeLast()
            val name = current.name
            if (name.startsWith(".")) continue
            val absolute = try {
                current.absolutePath
            } catch (_: Exception) {
                continue
            }
            if (isSkipped(absolute, skip)) continue
            val isDir = try {
                current.isDirectory
            } catch (_: Exception) {
                false
            }
            if (isDir) {
                if (depth > MAX_DEPTH) continue
                val canonical = try {
                    current.canonicalPath
                } catch (_: Exception) {
                    absolute
                }
                if (!seenDirs.add(canonical)) continue
            }
            out.add(toIndexed(current, absolute, name, isDir))
            if (out.size >= MAX_ENTRIES) break
            if (out.size % 2000 == 0) onProgress(out.size)
            if (!isDir) continue
            val children = try {
                current.listFiles()
            } catch (_: Exception) {
                null
            } ?: continue
            for (child in children) {
                if (!child.name.startsWith(".")) stack.add(child to depth + 1)
            }
        }
        return out
    }

    private suspend fun walkSubtree(start: File, skip: List<String>): List<IndexedFile> {
        val out = ArrayList<IndexedFile>()
        val stack = ArrayDeque<Pair<File, Int>>()
        val seenDirs = HashSet<String>()
        stack.add(start to 0)
        var ops = 0
        while (stack.isNotEmpty()) {
            if ((ops++ and 31) == 0) currentCoroutineContext().ensureActive()
            val (current, depth) = stack.removeLast()
            if (current.name.startsWith(".")) continue
            val absolute = try {
                current.absolutePath
            } catch (_: Exception) {
                continue
            }
            if (isSkipped(absolute, skip)) continue
            val isDir = try {
                current.isDirectory
            } catch (_: Exception) {
                false
            }
            if (isDir) {
                if (depth > MAX_DEPTH) continue
                val canonical = try {
                    current.canonicalPath
                } catch (_: Exception) {
                    absolute
                }
                if (!seenDirs.add(canonical)) continue
            }
            out.add(toIndexed(current, absolute, current.name, isDir))
            if (out.size >= 5000) break
            if (!isDir) continue
            val children = try {
                current.listFiles()
            } catch (_: Exception) {
                null
            } ?: continue
            for (child in children) {
                if (!child.name.startsWith(".")) stack.add(child to depth + 1)
            }
        }
        return out
    }

    private fun toIndexed(file: File, absolute: String, name: String, isDir: Boolean): IndexedFile {
        val size = if (isDir) {
            0L
        } else {
            try {
                file.length()
            } catch (_: Exception) {
                0L
            }
        }
        val modified = try {
            file.lastModified()
        } catch (_: Exception) {
            0L
        }
        val dot = name.lastIndexOf('.')
        val ext = if (!isDir && dot > 0) name.substring(dot + 1).lowercase(Locale.ROOT) else ""
        return IndexedFile(
            file = file,
            path = absolute,
            name = name,
            lowerName = normalize(name),
            lowerPath = normalize(absolute),
            isDirectory = isDir,
            extension = ext,
            size = size,
            lastModified = modified
        )
    }

    private fun skipPrefixes(root: File): List<String> {
        val base = root.absolutePath.trimEnd('/')
        return listOf(base + "/Android/data", base + "/Android/obb")
    }

    private fun isSkipped(absolute: String, skip: List<String>): Boolean {
        for (prefix in skip) {
            if (absolute == prefix || absolute.startsWith(prefix + "/")) return true
        }
        return false
    }

    private fun getCached(key: String): List<IndexedFile>? = synchronized(searchCache) {
        searchCache[key]
    }

    private fun putCached(key: String, value: List<IndexedFile>) = synchronized(searchCache) {
        searchCache[key] = value
    }

    private fun clearCache() = synchronized(searchCache) {
        searchCache.clear()
    }
}
