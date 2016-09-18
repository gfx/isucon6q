worker_processes 5
preload_app true
timeout 120

stderr_path "/tmp/unicorn-err.log"
stdout_path "/tmp/unicorn-out.log"
