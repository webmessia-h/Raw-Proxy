#include "../include/threadpool.hpp"

ThreadPool::ThreadPool(int numThr) : stop(false) {
  for (int i = 0; i < numThr; ++i) {
    threads.emplace_back([this]() {
      while (true) {
        std::function<void()> task;
        {
          std::unique_lock<std::mutex> lock(qMutex);
          cond.wait(lock, [this] { return stop || !tasks.empty(); });
          if (stop && tasks.empty())
            return;

          task = std::move(tasks.front());
          tasks.pop();
        }
        task();
      }
    });
  }
}

void ThreadPool::enqueue(std::function<void()> task) {
  {
    std::unique_lock<std::mutex> lock(qMutex);
    tasks.push(std::move(task));
  }
  cond.notify_one();
}

void ThreadPool::stopped() {
  {
    std::unique_lock<std::mutex> lock(qMutex);
    stop = true;
  }
  cond.notify_all();
}

ThreadPool::~ThreadPool() {
  stopped();
  for (std::thread &worker : threads) {
    worker.join();
  }
}
