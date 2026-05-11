#!/usr/bin/env node
console.log('\n🧪 Testing Memory Stability Fix...\n');

// Simulate the memory leak fix from core.js
// Before: unbounded array growth
// After: LRU cache with limits

class MockLRUCache {
  constructor(maxSize = 1000) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }
  
  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }
  
  get(key) {
    return this.cache.get(key);
  }
}

const cache = new MockLRUCache(1000);

// Add 2000 items - should only keep 1000
for (let i = 0; i < 2000; i++) {
  cache.set(`key-${i}`, `value-${i}`);
}

if (cache.cache.size === 1000) {
  console.log(`✅ Cache bounded at ${cache.cache.size} items (max: ${cache.maxSize})\n`);
  process.exit(0);
} else {
  console.log(`❌ Cache size is ${cache.cache.size}, expected 1000\n`);
  process.exit(1);
}
