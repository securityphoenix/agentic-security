// Coupon display logic only — read access, no mutation. Should NOT fire.
import React from 'react';

export default function CouponBadge({ coupon }) {
  return (
    <div>
      <span>{coupon.label}</span>
      <strong>{coupon.amount}</strong>
      <em>{discount.description}</em>
    </div>
  );
}
