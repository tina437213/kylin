/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

package org.apache.kylin.rest.service;

import java.io.IOException;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.annotation.Nullable;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.util.Strings;
import org.apache.kylin.common.KylinConfig;
import org.apache.kylin.common.util.ClassUtil;
import org.apache.kylin.common.util.Pair;
import org.apache.kylin.cube.CubeInstance;
import org.apache.kylin.cube.CubeSegment;
import org.apache.kylin.cube.CubeUpdate;
import org.apache.kylin.cube.model.CubeBuildTypeEnum;
import org.apache.kylin.engine.EngineFactory;
import org.apache.kylin.engine.mr.BatchOptimizeJobCheckpointBuilder;
import org.apache.kylin.engine.mr.CubingJob;
import org.apache.kylin.engine.mr.common.JobInfoConverter;
import org.apache.kylin.engine.mr.steps.CubingExecutableUtil;
import org.apache.kylin.job.JobInstance;
import org.apache.kylin.job.Scheduler;
import org.apache.kylin.job.SchedulerFactory;
import org.apache.kylin.job.constant.JobStatusEnum;
import org.apache.kylin.job.constant.JobTimeFilterEnum;
import org.apache.kylin.job.engine.JobEngineConfig;
import org.apache.kylin.job.exception.JobException;
import org.apache.kylin.job.exception.SchedulerException;
import org.apache.kylin.job.execution.AbstractExecutable;
import org.apache.kylin.job.execution.CheckpointExecutable;
import org.apache.kylin.job.execution.DefaultChainedExecutable;
import org.apache.kylin.job.execution.ExecutableState;
import org.apache.kylin.job.execution.Output;
import org.apache.kylin.job.lock.JobLock;
import org.apache.kylin.metadata.model.SegmentStatusEnum;
import org.apache.kylin.metadata.realization.RealizationStatusEnum;
import org.apache.kylin.rest.constant.Constant;
import org.apache.kylin.rest.exception.BadRequestException;
import org.apache.kylin.rest.msg.Message;
import org.apache.kylin.rest.msg.MsgPicker;
import org.apache.kylin.source.ISource;
import org.apache.kylin.source.SourceFactory;
import org.apache.kylin.source.SourcePartition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.FluentIterable;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

/**
 * @author ysong1
 */

@EnableAspectJAutoProxy(proxyTargetClass = true)
@Component("jobService")
public class JobService extends BasicService implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(JobService.class);

    private JobLock jobLock;

    @Autowired
    @Qualifier("accessService")
    private AccessService accessService;

    /*
    * (non-Javadoc)
    *
    * @see
    * org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
    */
    @SuppressWarnings("unchecked")
    @Override
    public void afterPropertiesSet() throws Exception {

        String timeZone = getConfig().getTimeZone();
        TimeZone tzone = TimeZone.getTimeZone(timeZone);
        TimeZone.setDefault(tzone);

        final KylinConfig kylinConfig = KylinConfig.getInstanceFromEnv();
        final Scheduler<AbstractExecutable> scheduler = (Scheduler<AbstractExecutable>) SchedulerFactory
                .scheduler(kylinConfig.getSchedulerType());

        jobLock = (JobLock) ClassUtil.newInstance(kylinConfig.getJobControllerLock());

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    scheduler.init(new JobEngineConfig(kylinConfig), jobLock);
                    if (!scheduler.hasStarted()) {
                        logger.info("scheduler has not been started");
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }).start();

        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    scheduler.shutdown();
                } catch (SchedulerException e) {
                    logger.error("error occurred to shutdown scheduler", e);
                }
            }
        }));
    }

    private Set<ExecutableState> convertStatusEnumToStates(List<JobStatusEnum> statusList) {
        Set<ExecutableState> states;
        if (statusList == null || statusList.isEmpty()) {
            states = EnumSet.allOf(ExecutableState.class);
        } else {
            states = Sets.newHashSet();
            for (JobStatusEnum status : statusList) {
                states.add(parseToExecutableState(status));
            }
        }
        return states;
    }

    private ExecutableState parseToExecutableState(JobStatusEnum status) {
        Message msg = MsgPicker.getMsg();

        switch (status) {
        case DISCARDED:
            return ExecutableState.DISCARDED;
        case ERROR:
            return ExecutableState.ERROR;
        case FINISHED:
            return ExecutableState.SUCCEED;
        case NEW:
            return ExecutableState.READY;
        case PENDING:
            return ExecutableState.READY;
        case RUNNING:
            return ExecutableState.RUNNING;
        case STOPPED:
            return ExecutableState.STOPPED;
        default:
            throw new BadRequestException(String.format(msg.getILLEGAL_EXECUTABLE_STATE(), status));
        }
    }

    private long getTimeStartInMillis(Calendar calendar, JobTimeFilterEnum timeFilter) {
        Message msg = MsgPicker.getMsg();

        switch (timeFilter) {
        case LAST_ONE_DAY:
            calendar.add(Calendar.DAY_OF_MONTH, -1);
            return calendar.getTimeInMillis();
        case LAST_ONE_WEEK:
            calendar.add(Calendar.WEEK_OF_MONTH, -1);
            return calendar.getTimeInMillis();
        case LAST_ONE_MONTH:
            calendar.add(Calendar.MONTH, -1);
            return calendar.getTimeInMillis();
        case LAST_ONE_YEAR:
            calendar.add(Calendar.YEAR, -1);
            return calendar.getTimeInMillis();
        case ALL:
            return 0;
        default:
            throw new BadRequestException(String.format(msg.getILLEGAL_TIME_FILTER(), timeFilter));
        }
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#cube, 'ADMINISTRATION') or hasPermission(#cube, 'OPERATION') or hasPermission(#cube, 'MANAGEMENT')")
    public JobInstance submitJob(CubeInstance cube, long startDate, long endDate, long startOffset, long endOffset, //
            Map<Integer, Long> sourcePartitionOffsetStart, Map<Integer, Long> sourcePartitionOffsetEnd,
            CubeBuildTypeEnum buildType, boolean force, String submitter) throws IOException {
        JobInstance jobInstance = submitJobInternal(cube, startDate, endDate, startOffset, endOffset, sourcePartitionOffsetStart,
                sourcePartitionOffsetEnd, buildType, force, submitter);

        accessService.init(jobInstance, null);
        accessService.inherit(jobInstance, cube);

        return jobInstance;
    }

    public JobInstance submitJobInternal(CubeInstance cube, long startDate, long endDate, long startOffset,
            long endOffset, //
            Map<Integer, Long> sourcePartitionOffsetStart, Map<Integer, Long> sourcePartitionOffsetEnd,
            CubeBuildTypeEnum buildType, boolean force, String submitter) throws IOException {
        Message msg = MsgPicker.getMsg();

        if (cube.getStatus() == RealizationStatusEnum.DESCBROKEN) {
            throw new BadRequestException(String.format(msg.getBUILD_BROKEN_CUBE(), cube.getName()));
        }

        checkCubeDescSignature(cube);
        DefaultChainedExecutable job;

        CubeSegment newSeg = null;
        try {
            if (buildType == CubeBuildTypeEnum.BUILD) {
                ISource source = SourceFactory.getSource(cube);
                SourcePartition sourcePartition = new SourcePartition(startDate, endDate, startOffset, endOffset,
                        sourcePartitionOffsetStart, sourcePartitionOffsetEnd);
                sourcePartition = source.enrichSourcePartitionBeforeBuild(cube, sourcePartition);
                newSeg = getCubeManager().appendSegment(cube, sourcePartition);
                job = EngineFactory.createBatchCubingJob(newSeg, submitter);
            } else if (buildType == CubeBuildTypeEnum.MERGE) {
                newSeg = getCubeManager().mergeSegments(cube, startDate, endDate, startOffset, endOffset, force);
                job = EngineFactory.createBatchMergeJob(newSeg, submitter);
            } else if (buildType == CubeBuildTypeEnum.REFRESH) {
                newSeg = getCubeManager().refreshSegment(cube, startDate, endDate, startOffset, endOffset);
                job = EngineFactory.createBatchCubingJob(newSeg, submitter);
            } else {
                throw new BadRequestException(String.format(msg.getINVALID_BUILD_TYPE(), buildType));
            }

            getExecutableManager().addJob(job);

        } catch (Exception e) {
            if (newSeg != null) {
                logger.error("Job submission might failed for NEW segment {}, will clean the NEW segment from cube",
                        newSeg.getName());
                try {
                    // Remove this segments
                    CubeUpdate cubeBuilder = new CubeUpdate(cube);
                    cubeBuilder.setToRemoveSegs(newSeg);
                    getCubeManager().updateCube(cubeBuilder);
                } catch (Exception ee) {
                    // swallow the exception
                    logger.error("Clean New segment failed, ignoring it", e);
                }
            }
            throw e;
        }

        JobInstance jobInstance = getSingleJobInstance(job);

        return jobInstance;
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#cube, 'ADMINISTRATION') or hasPermission(#cube, 'OPERATION') or hasPermission(#cube, 'MANAGEMENT')")
    public Pair<JobInstance, List<JobInstance>> submitOptimizeJob(CubeInstance cube, Set<Long> cuboidsRecommend,
            String submitter) throws IOException, JobException {

        Pair<JobInstance, List<JobInstance>> result = submitOptimizeJobInternal(cube, cuboidsRecommend, submitter);
        accessService.init(result.getFirst(), null);
        accessService.inherit(result.getFirst(), cube);
        for (JobInstance jobInstance : result.getSecond()) {
            accessService.init(jobInstance, null);
            accessService.inherit(jobInstance, cube);
        }

        return result;
    }

    private Pair<JobInstance, List<JobInstance>> submitOptimizeJobInternal(CubeInstance cube,
            Set<Long> cuboidsRecommend, String submitter) throws IOException {
        Message msg = MsgPicker.getMsg();

        if (cube.getStatus() == RealizationStatusEnum.DESCBROKEN) {
            throw new BadRequestException(String.format(msg.getBUILD_BROKEN_CUBE(), cube.getName()));
        }

        checkCubeDescSignature(cube);
        checkAllowOptimization(cube, cuboidsRecommend);

        CubeSegment[] optimizeSegments = null;
        try {
            /** Add optimize segments */
            optimizeSegments = getCubeManager().optimizeSegments(cube, cuboidsRecommend);
            List<JobInstance> optimizeJobInstances = Lists.newLinkedList();

            /** Add optimize jobs */
            List<AbstractExecutable> optimizeJobList = Lists.newArrayListWithExpectedSize(optimizeSegments.length);
            for (CubeSegment optimizeSegment : optimizeSegments) {
                DefaultChainedExecutable optimizeJob = EngineFactory.createBatchOptimizeJob(optimizeSegment, submitter);
                getExecutableManager().addJob(optimizeJob);

                optimizeJobList.add(optimizeJob);
                optimizeJobInstances.add(getSingleJobInstance(optimizeJob));
            }

            /** Add checkpoint job for batch jobs */
            CheckpointExecutable checkpointJob = new BatchOptimizeJobCheckpointBuilder(cube, submitter).build();
            checkpointJob.addTaskListForCheck(optimizeJobList);

            getExecutableManager().addJob(checkpointJob);

            return new Pair(getCheckpointJobInstance(checkpointJob), optimizeJobInstances);
        } catch (Exception e) {
            if (optimizeSegments != null) {
                logger.error("Job submission might failed for NEW segments {}, will clean the NEW segments from cube",
                        optimizeSegments);
                try {
                    // Remove this segments
                    CubeUpdate cubeBuilder = new CubeUpdate(cube);
                    cubeBuilder.setToRemoveSegs(optimizeSegments);
                    getCubeManager().updateCube(cubeBuilder);
                } catch (Exception ee) {
                    // swallow the exception
                    logger.error("Clean New segments failed, ignoring it", e);
                }
            }
            throw e;
        }
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#cube, 'ADMINISTRATION') or hasPermission(#cube, 'OPERATION') or hasPermission(#cube, 'MANAGEMENT')")
    public JobInstance submitRecoverSegmentOptimizeJob(CubeSegment segment, String submitter)
            throws IOException, JobException {
        CubeInstance cubeInstance = segment.getCubeInstance();

        checkCubeDescSignature(cubeInstance);

        String cubeName = cubeInstance.getName();
        List<JobInstance> jobInstanceList = searchJobsByCubeName(cubeName, null,
                Lists.newArrayList(JobStatusEnum.NEW, JobStatusEnum.PENDING, JobStatusEnum.ERROR),
                JobTimeFilterEnum.ALL, JobSearchMode.CHECKPOINT_ONLY);
        if (jobInstanceList.size() > 1) {
            throw new IllegalStateException("Exist more than one CheckpointExecutable for cube " + cubeName);
        } else if (jobInstanceList.size() == 0) {
            throw new IllegalStateException("There's no CheckpointExecutable for cube " + cubeName);
        }
        CheckpointExecutable checkpointExecutable = (CheckpointExecutable) getExecutableManager()
                .getJob(jobInstanceList.get(0).getId());

        AbstractExecutable toBeReplaced = null;
        for (AbstractExecutable taskForCheck : checkpointExecutable.getSubTasksForCheck()) {
            if (taskForCheck instanceof CubingJob) {
                CubingJob subCubingJob = (CubingJob) taskForCheck;
                String segmentName = CubingExecutableUtil.getSegmentName(subCubingJob.getParams());
                if (segmentName != null && segmentName.equals(segment.getName())) {
                    String segmentID = CubingExecutableUtil.getSegmentId(subCubingJob.getParams());
                    CubeSegment beingOptimizedSegment = cubeInstance.getSegmentById(segmentID);
                    if (beingOptimizedSegment != null) { // beingOptimizedSegment exists & should not be recovered
                        throw new IllegalStateException("Segment " + beingOptimizedSegment.getName() + "-"
                                + beingOptimizedSegment.getUuid()
                                + " still exists. Please delete it or discard the related optimize job first!!!");
                    }
                    toBeReplaced = taskForCheck;
                    break;
                }
            }
        }
        if (toBeReplaced == null) {
            throw new IllegalStateException("There's no CubingJob for segment " + segment.getName()
                    + " in CheckpointExecutable " + checkpointExecutable.getName());
        }

        /** Add CubingJob for the related segment **/
        CubeSegment optimizeSegment = getCubeManager().appendSegment(cubeInstance, segment.getDateRangeStart(),
                segment.getDateRangeEnd());
        CubeUpdate cubeBuilder = new CubeUpdate(cubeInstance);
        cubeBuilder.setToAddSegs(optimizeSegment);
        getCubeManager().updateCube(cubeBuilder);

        DefaultChainedExecutable optimizeJob = EngineFactory.createBatchOptimizeJob(optimizeSegment, submitter);

        getExecutableManager().addJob(optimizeJob);

        JobInstance optimizeJobInstance = getSingleJobInstance(optimizeJob);
        accessService.init(optimizeJobInstance, null);
        accessService.inherit(optimizeJobInstance, cubeInstance);

        /** Update the checkpoint job */
        checkpointExecutable.getSubTasksForCheck().set(checkpointExecutable.getSubTasksForCheck().indexOf(toBeReplaced),
                optimizeJob);

        getExecutableManager().updateCheckpointJob(checkpointExecutable.getId(),
                checkpointExecutable.getSubTasksForCheck());

        return optimizeJobInstance;
    }

    private void checkCubeDescSignature(CubeInstance cube) {
        Message msg = MsgPicker.getMsg();

        if (!cube.getDescriptor().checkSignature())
            throw new BadRequestException(
                    String.format(msg.getINCONSISTENT_CUBE_DESC_SIGNATURE(), cube.getDescriptor()));
    }

    private void checkAllowOptimization(CubeInstance cube, Set<Long> cuboidsRecommend) {
        long baseCuboid = cube.getCuboidScheduler().getBaseCuboidId();
        if (!cuboidsRecommend.contains(baseCuboid)) {
            throw new BadRequestException("The recommend cuboids should contain the base cuboid " + baseCuboid);
        }
        Set<Long> currentCuboidSet = cube.getCuboidScheduler().getAllCuboidIds();
        if (currentCuboidSet.equals(cuboidsRecommend)) {
            throw new BadRequestException(
                    "The recommend cuboids are the same as the current cuboids. It's no need to do optimization.");
        }
    }

    public JobInstance getJobInstance(String uuid) {
        AbstractExecutable job = getExecutableManager().getJob(uuid);
        if (job instanceof CheckpointExecutable) {
            return getCheckpointJobInstance(job);
        } else {
            return getSingleJobInstance(job);
        }
    }

    public Output getOutput(String id) {
        return getExecutableManager().getOutput(id);
    }

    protected JobInstance getSingleJobInstance(AbstractExecutable job) {
        Message msg = MsgPicker.getMsg();

        if (job == null) {
            return null;
        }
        if (!(job instanceof CubingJob)) {
            throw new BadRequestException(String.format(msg.getILLEGAL_JOB_TYPE(), job.getId()));
        }

        CubingJob cubeJob = (CubingJob) job;
        final JobInstance result = new JobInstance();
        result.setName(job.getName());
        result.setRelatedCube(CubingExecutableUtil.getCubeName(cubeJob.getParams()));
        result.setRelatedSegment(CubingExecutableUtil.getSegmentId(cubeJob.getParams()));
        result.setLastModified(cubeJob.getLastModified());
        result.setSubmitter(cubeJob.getSubmitter());
        result.setUuid(cubeJob.getId());
        result.setType(CubeBuildTypeEnum.BUILD);
        result.setStatus(JobInfoConverter.parseToJobStatus(job.getStatus()));
        result.setMrWaiting(cubeJob.getMapReduceWaitTime() / 1000);
        result.setDuration(cubeJob.getDuration() / 1000);
        for (int i = 0; i < cubeJob.getTasks().size(); ++i) {
            AbstractExecutable task = cubeJob.getTasks().get(i);
            result.addStep(JobInfoConverter.parseToJobStep(task, i, getExecutableManager().getOutput(task.getId())));
        }
        return result;
    }

    protected JobInstance getCheckpointJobInstance(AbstractExecutable job) {
        Message msg = MsgPicker.getMsg();

        if (job == null) {
            return null;
        }
        if (!(job instanceof CheckpointExecutable)) {
            throw new BadRequestException(String.format(msg.getILLEGAL_JOB_TYPE(), job.getId()));
        }

        CheckpointExecutable checkpointExecutable = (CheckpointExecutable) job;
        final JobInstance result = new JobInstance();
        result.setName(job.getName());
        result.setRelatedCube(CubingExecutableUtil.getCubeName(job.getParams()));
        result.setLastModified(job.getLastModified());
        result.setSubmitter(job.getSubmitter());
        result.setUuid(job.getId());
        result.setType(CubeBuildTypeEnum.CHECKPOINT);
        result.setStatus(JobInfoConverter.parseToJobStatus(job.getStatus()));
        result.setDuration(job.getDuration() / 1000);
        for (int i = 0; i < checkpointExecutable.getTasks().size(); ++i) {
            AbstractExecutable task = checkpointExecutable.getTasks().get(i);
            result.addStep(JobInfoConverter.parseToJobStep(task, i, getExecutableManager().getOutput(task.getId())));
        }
        return result;
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#job, 'ADMINISTRATION') or hasPermission(#job, 'OPERATION') or hasPermission(#job, 'MANAGEMENT')")
    public void resumeJob(JobInstance job) {
        getExecutableManager().resumeJob(job.getId());
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#job, 'ADMINISTRATION') or hasPermission(#job, 'OPERATION') or hasPermission(#job, 'MANAGEMENT')")
    public void rollbackJob(JobInstance job, String stepId) {
        getExecutableManager().rollbackJob(job.getId(), stepId);
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#job, 'ADMINISTRATION') or hasPermission(#job, 'OPERATION') or hasPermission(#job, 'MANAGEMENT')")
    public JobInstance cancelJob(JobInstance job) throws IOException {
        if (null == job.getRelatedCube() || null == getCubeManager().getCube(job.getRelatedCube())) {
            getExecutableManager().discardJob(job.getId());
            return job;
        }

        logger.info("Cancel job [" + job.getId() + "] trigger by "
                + SecurityContextHolder.getContext().getAuthentication().getName());
        if (job.getStatus() == JobStatusEnum.FINISHED) {
            throw new IllegalStateException(
                    "The job " + job.getId() + " has already been finished and cannot be discarded.");
        }
        if (job.getStatus() == JobStatusEnum.DISCARDED) {
            return job;
        }

        AbstractExecutable executable = getExecutableManager().getJob(job.getId());
        if (executable instanceof CubingJob) {
            cancelCubingJobInner((CubingJob) executable);
        } else if (executable instanceof CheckpointExecutable) {
            cancelCheckpointJobInner((CheckpointExecutable) executable);
        } else {
            getExecutableManager().discardJob(executable.getId());
        }
        return job;
    }

    private void cancelCubingJobInner(CubingJob cubingJob) throws IOException {
        CubeInstance cubeInstance = getCubeManager().getCube(CubingExecutableUtil.getCubeName(cubingJob.getParams()));
        // might not a cube job
        final String segmentIds = CubingExecutableUtil.getSegmentId(cubingJob.getParams());
        if (!StringUtils.isEmpty(segmentIds)) {
            List<CubeSegment> toRemoveSegments = Lists.newLinkedList();
            for (String segmentId : StringUtils.split(segmentIds)) {
                final CubeSegment segment = cubeInstance.getSegmentById(segmentId);
                if (segment != null && segment.getStatus() != SegmentStatusEnum.READY) {
                    toRemoveSegments.add(segment);
                }
            }
            if (!toRemoveSegments.isEmpty()) {
                CubeUpdate cubeBuilder = new CubeUpdate(cubeInstance);
                cubeBuilder.setToRemoveSegs(toRemoveSegments.toArray(new CubeSegment[toRemoveSegments.size()]));
                getCubeManager().updateCube(cubeBuilder);
            }
        }
        getExecutableManager().discardJob(cubingJob.getId());
    }

    private void cancelCheckpointJobInner(CheckpointExecutable checkpointExecutable) throws IOException {
        List<String> segmentIdList = Lists.newLinkedList();
        List<String> jobIdList = Lists.newLinkedList();
        jobIdList.add(checkpointExecutable.getId());
        setRelatedIdList(checkpointExecutable, segmentIdList, jobIdList);

        CubeInstance cubeInstance = getCubeManager()
                .getCube(CubingExecutableUtil.getCubeName(checkpointExecutable.getParams()));
        if (!segmentIdList.isEmpty()) {
            List<CubeSegment> toRemoveSegments = Lists.newLinkedList();
            for (String segmentId : segmentIdList) {
                final CubeSegment segment = cubeInstance.getSegmentById(segmentId);
                if (segment != null && segment.getStatus() != SegmentStatusEnum.READY) {
                    toRemoveSegments.add(segment);
                }
            }

            CubeUpdate cubeBuilder = new CubeUpdate(cubeInstance);
            cubeBuilder.setToRemoveSegs(toRemoveSegments.toArray(new CubeSegment[toRemoveSegments.size()]));
            cubeBuilder.setCuboidsRecommend(Sets.<Long> newHashSet()); //Set recommend cuboids to be null
            getCubeManager().updateCube(cubeBuilder);
        }

        for (String jobId : jobIdList) {
            getExecutableManager().discardJob(jobId);
        }
    }

    private void setRelatedIdList(CheckpointExecutable checkpointExecutable, List<String> segmentIdList,
            List<String> jobIdList) {
        for (AbstractExecutable taskForCheck : checkpointExecutable.getSubTasksForCheck()) {
            jobIdList.add(taskForCheck.getId());
            if (taskForCheck instanceof CubingJob) {
                segmentIdList.addAll(Lists
                        .newArrayList(StringUtils.split(CubingExecutableUtil.getSegmentId(taskForCheck.getParams()))));
            } else if (taskForCheck instanceof CheckpointExecutable) {
                setRelatedIdList((CheckpointExecutable) taskForCheck, segmentIdList, jobIdList);
            }
        }
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#job, 'ADMINISTRATION') or hasPermission(#job, 'OPERATION') or hasPermission(#job, 'MANAGEMENT')")
    public JobInstance pauseJob(JobInstance job) {
        getExecutableManager().pauseJob(job.getId());
        return job;
    }

    @PreAuthorize(Constant.ACCESS_HAS_ROLE_ADMIN
            + " or hasPermission(#job, 'ADMINISTRATION') or hasPermission(#job, 'OPERATION') or hasPermission(#job, 'MANAGEMENT')")
    public void dropJob(JobInstance job) throws IOException {
        getExecutableManager().deleteJob(job.getId());
    }

    /**
     * currently only support substring match
     * @return
     */
    public List<JobInstance> searchJobs(final String cubeNameSubstring, final String projectName,
            final List<JobStatusEnum> statusList, final Integer limitValue, final Integer offsetValue,
            final JobTimeFilterEnum timeFilter) {
        Integer limit = (null == limitValue) ? 30 : limitValue;
        Integer offset = (null == offsetValue) ? 0 : offsetValue;
        List<JobInstance> jobs = searchJobsByCubeName(cubeNameSubstring, projectName, statusList, timeFilter);

        Collections.sort(jobs);

        if (jobs.size() <= offset) {
            return Collections.emptyList();
        }

        if ((jobs.size() - offset) < limit) {
            return jobs.subList(offset, jobs.size());
        }

        return jobs.subList(offset, offset + limit);
    }

    public List<JobInstance> searchJobsByCubeName(final String cubeNameSubstring, final String projectName,
            final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter) {
        return searchJobsByCubeName(cubeNameSubstring, projectName, statusList, timeFilter, JobSearchMode.ALL);
    }

    public List<JobInstance> searchJobsByCubeName(final String cubeNameSubstring, final String projectName,
            final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter, JobSearchMode jobSearchMode) {
        return innerSearchJobs(cubeNameSubstring, null, projectName, statusList, timeFilter, jobSearchMode);
    }

    public List<JobInstance> searchJobsByJobName(final String jobName, final String projectName,
            final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter) {
        return searchJobsByJobName(jobName, projectName, statusList, timeFilter, JobSearchMode.ALL);
    }

    public List<JobInstance> searchJobsByJobName(final String jobName, final String projectName,
            final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter, JobSearchMode jobSearchMode) {
        return innerSearchJobs(null, jobName, projectName, statusList, timeFilter, jobSearchMode);
    }

    public List<JobInstance> innerSearchJobs(final String cubeName, final String jobName, final String projectName,
            final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter, JobSearchMode jobSearchMode) {
        List<JobInstance> result = Lists.newArrayList();
        switch (jobSearchMode) {
        case CUBING_ONLY:
            result.addAll(innerSearchCubingJobs(cubeName, jobName, projectName, statusList, timeFilter));
            break;
        case CHECKPOINT_ONLY:
            result.addAll(innerSearchCheckpointJobs(cubeName, jobName, projectName, statusList, timeFilter));
            break;
        case ALL:
        default:
            result.addAll(innerSearchCubingJobs(cubeName, jobName, projectName, statusList, timeFilter));
            result.addAll(innerSearchCheckpointJobs(cubeName, jobName, projectName, statusList, timeFilter));
        }
        return result;
    }

    public List<JobInstance> innerSearchCubingJobs(final String cubeName, final String jobName,
            final String projectName, final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter) {
        // prepare time range
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        long timeStartInMillis = getTimeStartInMillis(calendar, timeFilter);
        long timeEndInMillis = Long.MAX_VALUE;
        Set<ExecutableState> states = convertStatusEnumToStates(statusList);
        final Map<String, Output> allOutputs = getExecutableManager().getAllOutputs(timeStartInMillis, timeEndInMillis);

        return Lists
                .newArrayList(
                        FluentIterable
                                .from(innerSearchCubingJobs(cubeName, jobName, states, timeStartInMillis,
                                        timeEndInMillis, allOutputs, false, projectName))
                                .transform(new Function<CubingJob, JobInstance>() {
                                    @Override
                                    public JobInstance apply(CubingJob cubingJob) {
                                        return JobInfoConverter.parseToJobInstance(cubingJob, allOutputs);
                                    }
                                }));
    }

    public List<CubingJob> innerSearchCubingJobs(final String cubeName, final String jobName,
            final Set<ExecutableState> statusList, long timeStartInMillis, long timeEndInMillis,
            final Map<String, Output> allOutputs, final boolean nameExactMatch, final String projectName) {
        List<CubingJob> results = Lists.newArrayList(FluentIterable.from(
                getExecutableManager().getAllAbstractExecutables(timeStartInMillis, timeEndInMillis, CubingJob.class))
                .filter(new Predicate<AbstractExecutable>() {
                    @Override
                    public boolean apply(AbstractExecutable executable) {
                        if (executable instanceof CubingJob) {
                            if (StringUtils.isEmpty(cubeName)) {
                                return true;
                            }
                            String executableCubeName = CubingExecutableUtil.getCubeName(executable.getParams());
                            if (executableCubeName == null)
                                return true;
                            if (nameExactMatch)
                                return executableCubeName.toLowerCase().equals(cubeName);
                            else
                                return executableCubeName.toLowerCase().contains(cubeName.toLowerCase());
                        } else {
                            return false;
                        }
                    }
                }).transform(new Function<AbstractExecutable, CubingJob>() {
                    @Override
                    public CubingJob apply(AbstractExecutable executable) {
                        return (CubingJob) executable;
                    }
                }).filter(Predicates.and(new Predicate<CubingJob>() {
                    @Override
                    public boolean apply(CubingJob executable) {
                        if (null == projectName || null == getProjectManager().getProject(projectName)) {
                            return true;
                        } else {
                            return projectName.equals(executable.getProjectName());
                        }
                    }
                }, new Predicate<CubingJob>() {
                    @Override
                    public boolean apply(CubingJob executable) {
                        try {
                            Output output = allOutputs.get(executable.getId());
                            if (output == null){
                                return false;
                            }
                            
                            ExecutableState state = output.getState();
                            boolean ret = statusList.contains(state);
                            return ret;
                        } catch (Exception e) {
                            throw e;
                        }
                    }
                }, new Predicate<CubingJob>() {
                    @Override
                    public boolean apply(@Nullable CubingJob cubeJob) {
                        if (cubeJob == null) {
                            return false;
                        }

                        if (Strings.isEmpty(jobName)) {
                            return true;
                        }

                        if (nameExactMatch) {
                            return cubeJob.getName().toLowerCase().equals(jobName);
                        } else {
                            return cubeJob.getName().toLowerCase().contains(jobName);
                        }
                    }
                })));
        return results;
    }

    public List<JobInstance> innerSearchCheckpointJobs(final String cubeName, final String jobName,
            final String projectName, final List<JobStatusEnum> statusList, final JobTimeFilterEnum timeFilter) {
        // prepare time range
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        long timeStartInMillis = getTimeStartInMillis(calendar, timeFilter);
        long timeEndInMillis = Long.MAX_VALUE;
        Set<ExecutableState> states = convertStatusEnumToStates(statusList);
        final Map<String, Output> allOutputs = getExecutableManager().getAllOutputs(timeStartInMillis, timeEndInMillis);

        return Lists
                .newArrayList(FluentIterable
                        .from(innerSearchCheckpointJobs(cubeName, jobName, states, timeStartInMillis, timeEndInMillis,
                                allOutputs, false, projectName))
                        .transform(new Function<CheckpointExecutable, JobInstance>() {
                            @Override
                            public JobInstance apply(CheckpointExecutable checkpointExecutable) {
                                return JobInfoConverter.parseToJobInstance(checkpointExecutable, allOutputs);
                            }
                        }));
    }

    public List<CheckpointExecutable> innerSearchCheckpointJobs(final String cubeName, final String jobName,
            final Set<ExecutableState> statusList, long timeStartInMillis, long timeEndInMillis,
            final Map<String, Output> allOutputs, final boolean nameExactMatch, final String projectName) {
        List<CheckpointExecutable> results = Lists
                .newArrayList(
                        FluentIterable
                                .from(getExecutableManager().getAllAbstractExecutables(timeStartInMillis,
                                        timeEndInMillis, CheckpointExecutable.class))
                                .filter(new Predicate<AbstractExecutable>() {
                                    @Override
                                    public boolean apply(AbstractExecutable executable) {
                                        if (executable instanceof CheckpointExecutable) {
                                            if (StringUtils.isEmpty(cubeName)) {
                                                return true;
                                            }
                                            String executableCubeName = CubingExecutableUtil
                                                    .getCubeName(executable.getParams());
                                            if (executableCubeName == null)
                                                return true;
                                            if (nameExactMatch)
                                                return executableCubeName.toLowerCase().equals(cubeName);
                                            else
                                                return executableCubeName.toLowerCase()
                                                        .contains(cubeName.toLowerCase());
                                        } else {
                                            return false;
                                        }
                                    }
                                }).transform(new Function<AbstractExecutable, CheckpointExecutable>() {
                                    @Override
                                    public CheckpointExecutable apply(AbstractExecutable executable) {
                                        return (CheckpointExecutable) executable;
                                    }
                                }).filter(Predicates.and(new Predicate<CheckpointExecutable>() {
                                    @Override
                                    public boolean apply(CheckpointExecutable executable) {
                                        if (null == projectName
                                                || null == getProjectManager().getProject(projectName)) {
                                            return true;
                                        } else {
                                            return projectName.equals(executable.getProjectName());
                                        }
                                    }
                                }, new Predicate<CheckpointExecutable>() {
                                    @Override
                                    public boolean apply(CheckpointExecutable executable) {
                                        try {
                                            Output output = allOutputs.get(executable.getId());
                                            if (output == null) {
                                                return false;
                                            }

                                            ExecutableState state = output.getState();
                                            boolean ret = statusList.contains(state);
                                            return ret;
                                        } catch (Exception e) {
                                            throw e;
                                        }
                                    }
                                }, new Predicate<CheckpointExecutable>() {
                                    @Override
                                    public boolean apply(@Nullable CheckpointExecutable checkpointExecutable) {
                                        if (checkpointExecutable == null) {
                                            return false;
                                        }

                                        if (Strings.isEmpty(jobName)) {
                                            return true;
                                        }

                                        if (nameExactMatch) {
                                            return checkpointExecutable.getName().toLowerCase().equals(jobName);
                                        } else {
                                            return checkpointExecutable.getName().toLowerCase().contains(jobName);
                                        }
                                    }
                                })));
        return results;
    }

    public List<CubingJob> listJobsByRealizationName(final String realizationName, final String projectName,
            final Set<ExecutableState> statusList) {
        return innerSearchCubingJobs(realizationName, null, statusList, 0L, Long.MAX_VALUE,
                getExecutableManager().getAllOutputs(), true, projectName);
    }

    public List<CubingJob> listJobsByRealizationName(final String realizationName, final String projectName) {
        return listJobsByRealizationName(realizationName, projectName, EnumSet.allOf(ExecutableState.class));
    }

    public enum JobSearchMode {
        CUBING_ONLY, CHECKPOINT_ONLY, ALL
    }
}
