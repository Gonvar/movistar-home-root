# Upstream fixes for CVE-2021-1905

These are the patches our device tree lacks. Reproduced here for reference;
the authoritative copies live in the upstream kernel trees.

## Patch #1 — `d6770f2b86b6` ("CVE-2021-1905_1 KGSL")

Repo: `Hikari-no-Tenshi/android_kernel_oneplus_sm8150`
Committed-by: `<redacted-email>`

Removes the single shared `memdesc->useraddr` / `memdesc->mapsize` mapping
identity (invalid when one memdesc is mapped by several processes) and replaces
it with an `atomic_t map_count` plus a `check_vma(hostptr, size)` that walks
`find_vma()` and rejects vmas owned by `kgsl_fops`.

Representative shape:

```c
-   entry->memdesc.useraddr = vma->vm_start;
-   entry->memdesc.mapsize  = vma->vm_end - vma->vm_start;
+   atomic_inc(&entry->memdesc.map_count);
```

```c
+static bool check_vma(unsigned long hostptr, unsigned long size)
+{
+    struct vm_area_struct *vma;
+    vma = find_vma(current->mm, hostptr);
+    ...
+    /* reject vmas that belong to KGSL */
+    if (vma->vm_ops == &kgsl_gpumem_vm_ops)
+        return false;
+    ...
+}
```

## Patch #2 — `be897e2fa155` ("CVE-2021-1905_2 KGSL")

Repo: `Hikari-no-Tenshi/android_kernel_oneplus_sm8150`
Committed-by: `<redacted-email>`

Locks `_gpu_set_svm_region()` and refuses to re-assign `gpuaddr` — this is the
check whose absence gives our deterministic double-region trigger:

```c
 static unsigned long _gpu_set_svm_region(struct kgsl_process_private *private,
         struct kgsl_mem_entry *entry, unsigned long addr, unsigned long size)
 {
+    spin_lock(&entry->memdesc.lock);
+    if (entry->memdesc.gpuaddr) {
+        spin_unlock(&entry->memdesc.lock);
+        return -EBUSY;
+    }
     ...
     ret = kgsl_mmu_set_svm_region(private->pagetable, addr, size);
-    if (ret) return ret;
+    if (ret) { spin_unlock(&entry->memdesc.lock); return ret; }
     entry->memdesc.gpuaddr = addr;
     ...
     ret = kgsl_mmu_map(private->pagetable, &entry->memdesc);
     ...
+    spin_unlock(&entry->memdesc.lock);
     return addr;
 }
```

plus `_search_range()` propagating `-EBUSY`.

## Earlier 3.18 hardening (facilitator, not the 1905 bug)

`0a4ef64e3f` — vendor, Deepak Kumar, 2017-05-08 (upstream-identical text at
`0e42ef24…`):

```c
  idr_for_each_entry(&private->mem_idr, entry, id) {
      if (GPUADDR_IN_MEMDESC(gpuaddr, &entry->memdesc)) {
-         ret = kgsl_mem_entry_get(entry);
+         if (!entry->pending_free)
+             ret = kgsl_mem_entry_get(entry);
          break;
      }
  }
```

This only guards `kgsl_sharedmem_find()` **by gpuaddr**; our device lacks it too.

## References

* NVD CVE-2021-1905 — *"Possible use after free due to improper handling of
  memory mapping of multiple processes simultaneously."*
* Android Security Bulletin, May 2021 (CVE-2021-1905 / CVE-2021-1906).
