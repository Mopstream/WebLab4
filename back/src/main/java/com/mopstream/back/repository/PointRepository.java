package com.mopstream.back.repository;

import com.mopstream.back.models.Point;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PointRepository extends JpaRepository<Point, Integer> {
    List<Point> findAllByOwnerId(Long id);
    void deleteAllByOwnerId(Long id);
}