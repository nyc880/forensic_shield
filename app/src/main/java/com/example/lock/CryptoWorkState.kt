package com.example.lock

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

object CryptoWorkState {

    enum class Status { IDLE, RUNNING, SUCCEEDED, FAILED, CANCELLED }

    private val workScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    var isCancelled: Boolean = false
        private set

    private val _status = MutableStateFlow(Status.IDLE)
    val status: StateFlow<Status> = _status

    private val _progress = MutableStateFlow(0)
    val progress: StateFlow<Int> = _progress

    private val _stage = MutableStateFlow("")
    val stage: StateFlow<String> = _stage

    private val _message = MutableStateFlow("")
    val message: StateFlow<String> = _message

    @Volatile
    var job: Job? = null
        private set

    fun start() {
        isCancelled = false
        _progress.value = 0
        _stage.value = ""
        _message.value = ""
        _status.value = Status.RUNNING
    }

    fun launchWork(block: suspend () -> Unit): Job {
        val started = workScope.launch {
            try {
                block()
            } finally {
                job = null
            }
        }
        job = started
        return started
    }

    fun requestCancel() {
        if (_status.value != Status.RUNNING) return
        isCancelled = true
        _status.value = Status.CANCELLED
        job?.cancel()
    }

    fun setProgress(value: Int) {
        val clamped = value.coerceIn(0, 100)
        if (_progress.value != clamped) _progress.value = clamped
    }

    fun setStage(value: String) {
        _stage.value = value
    }

    fun succeed(message: String = "") {
        isCancelled = false
        _progress.value = 100
        _message.value = message
        _status.value = Status.SUCCEEDED
    }

    fun fail(message: String) {
        _message.value = message
        _status.value = Status.FAILED
    }

    fun markCancelled() {
        _message.value = "Operation was cancelled by user."
        _status.value = Status.CANCELLED
    }
}
