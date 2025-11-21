#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

/// Retourne une page clonée depuis `slice`, en bornant offset/limit.
/// - `max_limit` définit la limite supérieure autorisée (0 = illimité).
/// - `limit=0` tombe automatiquement sur `max_limit` (ou 1 si les deux sont à 0).
pub fn paginate_slice<T: Clone>(slice: &[T], request: PageRequest, max_limit: usize) -> Page<T> {
    let total = slice.len();
    let hard_cap = if max_limit == 0 {
        usize::MAX
    } else {
        max_limit
    };

    let limit = if request.limit == 0 {
        hard_cap
    } else {
        request.limit.min(hard_cap)
    };
    let effective_limit = limit.max(1);

    let offset = request.offset.min(total);
    let end = offset.saturating_add(effective_limit).min(total);

    Page {
        items: slice[offset..end].to_vec(),
        total,
        offset,
        limit: effective_limit,
    }
}

#[cfg(test)]
mod tests {
    use super::{paginate_slice, PageRequest};

    #[test]
    fn paginates_within_bounds() {
        let items = vec![1, 2, 3, 4, 5];
        let page = paginate_slice(
            &items,
            PageRequest {
                offset: 1,
                limit: 2,
            },
            10,
        );
        assert_eq!(page.items, vec![2, 3]);
        assert_eq!(page.total, 5);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 2);
    }

    #[test]
    fn clamps_offset_beyond_total() {
        let items = vec![1, 2, 3];
        let page = paginate_slice(
            &items,
            PageRequest {
                offset: 10,
                limit: 2,
            },
            5,
        );
        assert!(page.items.is_empty());
        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 3);
        assert_eq!(page.limit, 2);
    }

    #[test]
    fn clamps_limit_to_cap() {
        let items = vec![1, 2, 3, 4];
        let page = paginate_slice(
            &items,
            PageRequest {
                offset: 0,
                limit: 10,
            },
            3,
        );
        assert_eq!(page.items, vec![1, 2, 3]);
        assert_eq!(page.total, 4);
        assert_eq!(page.offset, 0);
        assert_eq!(page.limit, 3);
    }

    #[test]
    fn limit_zero_uses_cap_or_min_one() {
        let items = vec![1, 2, 3];
        let page = paginate_slice(
            &items,
            PageRequest {
                offset: 0,
                limit: 0,
            },
            0,
        );
        assert_eq!(page.items, vec![1, 2, 3]);
        assert_eq!(page.limit, usize::MAX);

        let capped = paginate_slice(
            &items,
            PageRequest {
                offset: 0,
                limit: 0,
            },
            2,
        );
        assert_eq!(capped.items.len(), 2);
        assert_eq!(capped.limit, 2);
    }
}
