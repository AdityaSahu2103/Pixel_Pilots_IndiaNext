'use client';

import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';

function Particles({ count = 300 }) {
  const meshRef = useRef();

  const [positions, speeds] = useMemo(() => {
    const pos = new Float32Array(count * 3);
    const spd = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      pos[i * 3] = (Math.random() - 0.5) * 20;
      pos[i * 3 + 1] = (Math.random() - 0.5) * 20;
      pos[i * 3 + 2] = (Math.random() - 0.5) * 20;
      spd[i] = Math.random() * 0.01 + 0.002;
    }
    return [pos, spd];
  }, [count]);

  useFrame(() => {
    if (!meshRef.current) return;
    const posArr = meshRef.current.geometry.attributes.position.array;
    for (let i = 0; i < count; i++) {
      posArr[i * 3 + 1] += speeds[i];
      if (posArr[i * 3 + 1] > 10) {
        posArr[i * 3 + 1] = -10;
      }
    }
    meshRef.current.geometry.attributes.position.needsUpdate = true;
  });

  return (
    <points ref={meshRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={count}
          array={positions}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        color="#00F5FF"
        size={0.03}
        transparent
        opacity={0.4}
        sizeAttenuation
      />
    </points>
  );
}

export default function ParticleField({ className = '' }) {
  return (
    <div className={`absolute inset-0 pointer-events-none ${className}`} style={{ zIndex: 0 }}>
      <Canvas
        camera={{ position: [0, 0, 5], fov: 60 }}
        style={{ background: 'transparent' }}
        gl={{ alpha: true }}
      >
        <Particles />
      </Canvas>
    </div>
  );
}
