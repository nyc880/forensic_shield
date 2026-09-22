package com.example.lock.search

import java.util.Locale
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

class SearchIndexManager<T> {

    private class IndexedEntry<T>(
        val originalItem: T,
        val lowerNameChars: CharArray
    )

    private val indexedEntries = ArrayList<IndexedEntry<T>>()
    private val lock = ReentrantReadWriteLock()

    fun buildIndex(items: List<Pair<String, T>>) {
        lock.write {
            indexedEntries.clear()
            indexedEntries.ensureCapacity(items.size)
            val locale = Locale.getDefault()
            for (item in items) {
                val lowerName = item.first.lowercase(locale)
                indexedEntries.add(IndexedEntry(item.second, lowerName.toCharArray()))
            }
        }
    }

    fun search(query: String): List<T> {
        val trimmedQuery = query.trim()
        if (trimmedQuery.isEmpty()) return emptyList()

        val queryChars = trimmedQuery.lowercase(Locale.getDefault()).toCharArray()

        return lock.read {
            val results = ArrayList<T>()
            val entries = indexedEntries
            val size = entries.size

            for (i in 0 until size) {
                val entry = entries[i]
                if (containsSubarray(entry.lowerNameChars, queryChars)) {
                    results.add(entry.originalItem)
                }
            }
            results
        }
    }

    private fun containsSubarray(source: CharArray, target: CharArray): Boolean {
        val sourceLen = source.size
        val targetLen = target.size
        if (targetLen > sourceLen) return false
        if (targetLen == 0) return true

        val max = sourceLen - targetLen
        val first = target[0]

        for (i in 0..max) {
            if (source[i] == first) {
                var matched = true
                for (j in 1 until targetLen) {
                    if (source[i + j] != target[j]) {
                        matched = false
                        break
                    }
                }
                if (matched) return true
            }
        }
        return false
    }

    fun clear() {
        lock.write {
            indexedEntries.clear()
        }
    }
}